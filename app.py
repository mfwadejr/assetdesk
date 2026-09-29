import base64, csv, hashlib, hmac, http.server, io, os, secrets, sqlite3, struct, time, urllib.parse
from http import cookies

ROOT = os.path.dirname(__file__)
DB = os.environ.get('ASSETDESK_DB', os.path.join(ROOT, 'assets.sqlite3'))
SESSIONS = {}

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys = ON'); return c

def init():
    c=db(); c.executescript('''
    CREATE TABLE IF NOT EXISTS teams(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
    CREATE TABLE IF NOT EXISTS buildings(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, code TEXT NOT NULL DEFAULT '');
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'employee', team_id INTEGER REFERENCES teams(id), mfa INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS asset_types(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, code TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE IF NOT EXISTS assets(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), asset_type_id INTEGER NOT NULL REFERENCES asset_types(id), has_asset INTEGER NOT NULL DEFAULT 0, make TEXT, model TEXT, serial_number TEXT, asset_tag TEXT, updated_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, asset_type_id));
    CREATE TABLE IF NOT EXISTS user_buildings(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, building_id INTEGER NOT NULL REFERENCES buildings(id) ON DELETE CASCADE, PRIMARY KEY(user_id,building_id));
    ''')
    cols=[r['name'] for r in c.execute('PRAGMA table_info(users)').fetchall()]
    if 'totp_secret' not in cols: c.execute('ALTER TABLE users ADD COLUMN totp_secret TEXT')
    if c.execute('SELECT COUNT(*) n FROM teams').fetchone()['n']==0: c.executemany('INSERT INTO teams(name) VALUES(?)',[('Operations',),('Engineering',),('Finance',),('People & Culture',)])
    if c.execute('SELECT COUNT(*) n FROM buildings').fetchone()['n']==0: c.executemany('INSERT INTO buildings(name,code) VALUES(?,?)',[('Headquarters','HQ'),('North Campus','NC')])
    if c.execute('SELECT COUNT(*) n FROM asset_types').fetchone()['n']==0: c.executemany('INSERT INTO asset_types(name,code) VALUES(?,?)',[('Laptop (EMD)','EMD'),('Laptop (PMD)','PMD'),('Docking Station','DOCK'),('Monitor','MON'),('Mobile Phone','PHONE')])
    if c.execute('SELECT COUNT(*) n FROM users').fetchone()['n']==0:
        h=hashlib.sha256('admin123'.encode()).hexdigest(); tid=c.execute('SELECT id FROM teams LIMIT 1').fetchone()['id']; c.execute('INSERT INTO users(name,email,password,role,team_id,mfa) VALUES(?,?,?,?,?,?)',('Admin User','admin@example.com',h,'admin',tid,0))
    c.commit(); c.close()

def esc(s): return (s or '').replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;')
def totp(secret, counter=None):
    counter = int(time.time()//30) if counter is None else counter
    key=base64.b32decode(secret + '='*((8-len(secret)%8)%8), casefold=True); digest=hmac.new(key,struct.pack('>Q',counter),hashlib.sha1).digest(); off=digest[-1]&15
    return str((struct.unpack('>I',digest[off:off+4])[0]&0x7fffffff)%1000000).zfill(6)
def valid_totp(secret, code): return any(hmac.compare_digest(totp(secret,int(time.time()//30)+i),code) for i in (-1,0,1))
def page(title, body, user=None):
    nav = f'<span class="user">{esc(user["name"])} · {user["role"].title()}</span><a href="/logout">Log out</a>' if user else ''
    admin = '<a href="/admin">Admin</a>' if user and user['role'] in ('admin','lead') else ''
    return f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)} · AssetDesk</title><link rel="stylesheet" href="/static/style.css"></head><body><header><a class="brand" href="/">ASSET<span>DESK</span></a><nav>{admin}{nav}</nav></header><main>{body}</main></body></html>'''

class H(http.server.BaseHTTPRequestHandler):
    def send(self, body, status=200, ctype='text/html; charset=utf-8', headers=None):
        self.send_response(status); self.send_header('Content-Type',ctype); self.send_header('Content-Length',str(len(body))); [self.send_header(k,v) for k,v in (headers or {}).items()]; self.end_headers(); self.wfile.write(body if isinstance(body,bytes) else body.encode())
    def user(self):
        sid=cookies.SimpleCookie(self.headers.get('Cookie')).get('sid'); return db().execute('SELECT * FROM users WHERE id=?',(SESSIONS.get(sid.value) if sid else -1,)).fetchone() if sid and sid.value in SESSIONS else None
    def form(self): return urllib.parse.parse_qs(self.rfile.read(int(self.headers.get('Content-Length','0'))).decode())
    def redirect(self, path, sid=None): self.send_response(302); self.send_header('Location',path); (self.send_header('Set-Cookie',f'sid={sid}; HttpOnly; SameSite=Lax') if sid else None); self.end_headers()
    def do_GET(self):
        p=urllib.parse.urlparse(self.path); path=p.path; u=self.user(); c=db()
        if path.startswith('/static/'):
            fn=os.path.join(ROOT,path[1:]);
            try: self.send(open(fn,'rb').read(),ctype='text/css'); return
            except: self.send(b'not found',404); return
        if path=='/logout': self.redirect('/login'); return
        if path=='/login': self.send(page('Sign in','''<section class="auth"><div class="eyebrow">INTERNAL ASSET REGISTER</div><h1>Sign in to AssetDesk</h1><p class="muted">Track equipment by team, person, and asset tag.</p><form method="post"><label>Email<input name="email" type="email" required placeholder="you@company.com"></label><label>Password<input name="password" type="password" required></label><button>Sign in</button><p class="hint">Demo admin: admin@example.com / admin123</p></form></section>''')); return
        if not u: self.redirect('/login'); return
        if path=='/export.csv':
            rows=c.execute('''SELECT u.name employee,t.name team,at.name asset_type,a.has_asset,a.make,a.model,a.serial_number,a.asset_tag FROM assets a JOIN users u ON u.id=a.user_id JOIN teams t ON t.id=u.team_id JOIN asset_types at ON at.id=a.asset_type_id ORDER BY t.name,u.name,at.name''').fetchall(); out=io.StringIO(); w=csv.writer(out); w.writerow(rows[0].keys() if rows else ['employee','team','asset_type','has_asset','make','model','serial_number','asset_tag']); [w.writerow(list(r)) for r in rows]; self.send(out.getvalue().encode(),ctype='text/csv',headers={'Content-Disposition':'attachment; filename=asset-register.csv'}); return
        if path=='/admin' and u['role'] in ('admin','lead'):
            query=urllib.parse.parse_qs(p.query); team_filter=query.get('team',[''])[0]; employee_filter=query.get('employee',[''])[0]; search=query.get('q',[''])[0].strip(); teams=c.execute('SELECT * FROM teams ORDER BY name').fetchall(); employees=c.execute('SELECT id,name,team_id FROM users ORDER BY name').fetchall(); where=''; args=[]
            if u['role']=='lead': where='WHERE u.team_id=?'; args=[u['team_id']]
            elif team_filter: where='WHERE u.team_id=?'; args=[team_filter]
            if employee_filter: where += (' AND ' if where else 'WHERE ')+'u.id=?'; args.append(employee_filter)
            if search:
                where += (' AND ' if where else 'WHERE ')+'(u.name LIKE ? OR at.name LIKE ? OR a.make LIKE ? OR a.model LIKE ? OR a.serial_number LIKE ? OR a.asset_tag LIKE ?)'; args += [f'%{search}%']*6
            rows=c.execute(f'''SELECT u.name employee,t.name team,at.name asset_type,a.has_asset,a.make,a.model,a.serial_number,a.asset_tag FROM assets a JOIN users u ON u.id=a.user_id JOIN teams t ON t.id=u.team_id JOIN asset_types at ON at.id=a.asset_type_id {where} ORDER BY t.name,u.name,at.name''',args).fetchall()
            tr=''.join(f'<tr><td>{esc(r["employee"])}</td><td>{esc(r["team"])}</td><td>{esc(r["asset_type"])}</td><td>{"Yes" if r["has_asset"] else "No"}</td><td>{esc(r["make"])}</td><td>{esc(r["model"])}</td><td>{esc(r["serial_number"])}</td><td>{esc(r["asset_tag"])}</td></tr>' for r in rows)
            tsel=''.join(f'<option value="{t["id"]}" {"selected" if str(t["id"])==team_filter else ""}>{esc(t["name"])}</option>' for t in teams) if u['role']=='admin' else ''
            esel=''.join(f'<option value="{e["id"]}" data-team="{e["team_id"]}" {"selected" if str(e["id"])==employee_filter else ""}>{esc(e["name"])}</option>' for e in employees)
            body=f'<div class="pagehead"><div><div class="eyebrow">ADMINISTRATION</div><h1>Asset register</h1><p class="muted">Review employee equipment and export a clean report.</p></div><div class="actions"><a class="button secondary" href="/export.csv">Export Excel-compatible CSV</a><button onclick="window.print()">Print / save PDF</button></div></div><section class="panel"><form class="filters"><label>Team<select id="teamFilter" name="team" onchange="filterEmployees();this.form.submit()"><option value="">All teams</option>{tsel}</select></label><label>Employee<select id="employeeFilter" name="employee"><option value="">All employees</option>{esel}</select></label><label>Search<input name="q" value="{esc(search)}" placeholder="Search assets…"></label><button>Apply</button><span class="count">{len(rows)} rows</span></form><div class="tablewrap"><table><thead><tr><th>Employee</th><th>Team</th><th>Asset</th><th>Has it?</th><th>Make</th><th>Model</th><th>Serial</th><th>Asset tag</th></tr></thead><tbody>{tr or "<tr><td colspan=8 class=empty>No submissions yet.</td></tr>"}</tbody></table></div></section><script>function filterEmployees(){{let t=document.getElementById("teamFilter").value;document.querySelectorAll("#employeeFilter option[data-team]").forEach(o=>o.hidden=!!t&&o.dataset.team!==t);}}</script>'
            if u['role']=='admin':
                asset_types='<section class="panel admin-panel"><h2>Asset types</h2><form method="post" action="/admin/type" class="inlineform"><input name="name" placeholder="e.g. Headset" required><input name="code" placeholder="Code" required><button>Add asset type</button></form><div class="chips">'+''.join(f'<span>{esc(a["name"])} <small>{esc(a["code"])}</small> <button class="chip-delete" form="del-a{a["id"]}">×</button></span><form id="del-a{a["id"]}" method="post" action="/admin/delete/asset-type/{a["id"]}" onsubmit="return confirm("Delete this asset type and its records?")"></form>' for a in c.execute('SELECT * FROM asset_types ORDER BY name'))+'</div></section>'
                team_list='<section class="panel admin-panel"><h2>Teams</h2><form method="post" action="/admin/team" class="inlineform"><input name="name" placeholder="Team name" required><button>Add team</button></form><div class="chips">'+''.join(f'<span>{esc(t["name"])} <button class="chip-delete" form="del-t{t["id"]}">×</button></span><form id="del-t{t["id"]}" method="post" action="/admin/delete/team/{t["id"]}" onsubmit="return confirm("Delete this team?")"></form>' for t in c.execute('SELECT * FROM teams ORDER BY name'))+'</div></section>'
                building_list='<section class="panel admin-panel"><h2>Buildings</h2><form method="post" action="/admin/building" class="inlineform"><input name="name" placeholder="Building name" required><input name="code" placeholder="Code"><button>Add building</button></form><div class="chips">'+''.join(f'<span>{esc(b["name"])} <small>{esc(b["code"])}</small> <button class="chip-delete" form="del-b{b["id"]}">×</button></span><form id="del-b{b["id"]}" method="post" action="/admin/delete/building/{b["id"]}" onsubmit="return confirm("Delete this building?")"></form>' for b in c.execute('SELECT * FROM buildings ORDER BY name'))+'</div></section>'
                people='<section class="panel admin-panel"><h2>Personnel</h2><form method="post" action="/admin/user" class="inlineform"><input name="name" placeholder="Full name" required><input name="email" type="email" placeholder="Email" required><input name="password" placeholder="Temporary password" required><select name="team_id">'+''.join(f'<option value="{t["id"]}">{esc(t["name"])}</option>' for t in teams)+'</select><select name="role"><option value="employee">Employee</option><option value="lead">Team Lead</option><option value="admin">Admin</option></select><button>Add person</button></form><div class="chips">'+''.join(f'<span>{esc(p["name"])} · {esc(c.execute("SELECT name FROM teams WHERE id=?",(p["team_id"],)).fetchone()["name"] if p["team_id"] else "No team")} <button class="chip-delete" form="del-p{p["id"]}">×</button></span><form id="del-p{p["id"]}" method="post" action="/admin/delete/user/{p["id"]}" onsubmit="return confirm("Delete this person and their asset records?")"></form>' for p in c.execute('SELECT * FROM users ORDER BY name'))+'</div></section>'
                body += asset_types+team_list+building_list+people
            self.send(page('Admin',body,u)); return
        types=c.execute('SELECT * FROM asset_types WHERE active=1 ORDER BY id').fetchall(); existing={r['asset_type_id']:r for r in c.execute('SELECT * FROM assets WHERE user_id=?',(u['id'],))}; team=c.execute('SELECT name FROM teams WHERE id=?',(u['team_id'],)).fetchone()['name']; buildings=c.execute('SELECT * FROM buildings ORDER BY name').fetchall(); selected_buildings={r['building_id'] for r in c.execute('SELECT building_id FROM user_buildings WHERE user_id=?',(u['id'],))}; cards=''
        for a in types:
            x=existing.get(a['id']); yes=x and x['has_asset']; details=f'<div class="details" style="display:{"grid" if yes else "none"}"><input name="make_{a["id"]}" placeholder="Make" value="{esc(x["make"] if x else "")}"><input name="model_{a["id"]}" placeholder="Model" value="{esc(x["model"] if x else "")}"><input name="serial_{a["id"]}" placeholder="Serial number" value="{esc(x["serial_number"] if x else "")}"><input name="tag_{a["id"]}" placeholder="Asset tag" value="{esc(x["asset_tag"] if x else "")}"></div>'
            cards+=f'<article class="assetcard"><div><h3>{esc(a["name"])}</h3><p class="muted">Do you have this asset assigned to you?</p></div><div class="answer"><label><input type="radio" name="has_{a["id"]}" value="1" {"checked" if yes else ""} onchange="toggleDetails(this)"> Yes</label><label><input type="radio" name="has_{a["id"]}" value="0" {"checked" if not yes else ""} onchange="toggleDetails(this)"> No</label></div>{details}</article>'
        building_form='<section class="panel building-select"><h2>Building access</h2><p class="muted">Select the buildings this employee is authorized to access.</p><div class="building-options">'+''.join(f'<label><input type="checkbox" name="building" value="{b["id"]}" {"checked" if b["id"] in selected_buildings else ""}> {esc(b["name"])} <small>{esc(b["code"])}</small></label>' for b in buildings)+'</div></section>'
        body=f'<div class="pagehead"><div><div class="eyebrow">{esc(team).upper()} TEAM</div><h1>Your asset check-in</h1><p class="muted">Answer each question. Add identifying details when you have the asset.</p></div><span class="status">Autosave is off · submit when ready</span></div><form method="post" action="/save">{building_form}<div class="assetgrid">{cards}</div><button class="save">Save asset record</button></form><script>function toggleDetails(el){{let card=el.closest(".assetcard"),d=card.querySelector(".details");if(d)d.style.display=el.value=="1"?"grid":"none";}}</script>'
        self.send(page('My assets',body,u))
    def do_POST(self):
        path=urllib.parse.urlparse(self.path).path; f=self.form(); c=db()
        if path=='/login':
            email=f.get('email',[''])[0].lower(); pw=hashlib.sha256(f.get('password',[''])[0].encode()).hexdigest(); u=c.execute('SELECT * FROM users WHERE email=? AND password=?',(email,pw)).fetchone()
            if not u: self.send(page('Sign in','<section class="auth"><h1>Sign in failed</h1><p>Check your email and password.</p><a href="/login">Try again</a></section>'),401); return
            sid=secrets.token_urlsafe(24); SESSIONS[sid]=u['id']; self.redirect('/',sid); return
        u=self.user()
        if not u: self.redirect('/login'); return
        if path=='/save':
            c.execute('DELETE FROM user_buildings WHERE user_id=?',(u['id'],))
            c.executemany('INSERT INTO user_buildings(user_id,building_id) VALUES(?,?)',[(u['id'],int(b)) for b in f.get('building',[])])
            for a in c.execute('SELECT * FROM asset_types WHERE active=1'):
                has=int(f.get(f'has_{a["id"]}',['0'])[0]); vals=(u['id'],a['id'],has,f.get(f'make_{a["id"]}',[''])[0],f.get(f'model_{a["id"]}',[''])[0],f.get(f'serial_{a["id"]}',[''])[0],f.get(f'tag_{a["id"]}',[''])[0]); c.execute('''INSERT INTO assets(user_id,asset_type_id,has_asset,make,model,serial_number,asset_tag) VALUES(?,?,?,?,?,?,?) ON CONFLICT(user_id,asset_type_id) DO UPDATE SET has_asset=excluded.has_asset,make=excluded.make,model=excluded.model,serial_number=excluded.serial_number,asset_tag=excluded.asset_tag,updated_at=CURRENT_TIMESTAMP''',vals)
            c.commit(); self.send(page('Saved','<section class="success"><div class="eyebrow">RECORD SAVED</div><h1>Thanks — your assets are up to date.</h1><p class="muted">Your team lead can now see the latest details in the register.</p><a class="button" href="/">Back to my assets</a></section>',u)); return
        if path=='/admin/type' and u['role']=='admin':
            try: c.execute('INSERT INTO asset_types(name,code) VALUES(?,?)',(f.get('name',[''])[0],f.get('code',[''])[0].upper())); c.commit()
            except sqlite3.IntegrityError: pass
            self.redirect('/admin'); return
        if path=='/admin/team' and u['role']=='admin':
            try: c.execute('INSERT INTO teams(name) VALUES(?)',(f.get('name',[''])[0],)); c.commit()
            except sqlite3.IntegrityError: pass
            self.redirect('/admin'); return
        if path=='/admin/building' and u['role']=='admin':
            try: c.execute('INSERT INTO buildings(name,code) VALUES(?,?)',(f.get('name',[''])[0],f.get('code',[''])[0].upper())); c.commit()
            except sqlite3.IntegrityError: pass
            self.redirect('/admin'); return
        if path=='/admin/user' and u['role']=='admin':
            try:
                pw=hashlib.sha256(f.get('password',[''])[0].encode()).hexdigest(); c.execute('INSERT INTO users(name,email,password,role,team_id) VALUES(?,?,?,?,?)',(f.get('name',[''])[0],f.get('email',[''])[0].lower(),pw,f.get('role',['employee'])[0],f.get('team_id',[None])[0])); c.commit()
            except sqlite3.IntegrityError: pass
            self.redirect('/admin'); return
        if path.startswith('/admin/delete/') and u['role']=='admin':
            kind, ident = path.split('/')[-2:]
            try:
                ident=int(ident)
                if kind=='asset-type': c.execute('DELETE FROM assets WHERE asset_type_id=?',(ident,)); c.execute('DELETE FROM asset_types WHERE id=?',(ident,))
                elif kind=='building': c.execute('DELETE FROM user_buildings WHERE building_id=?',(ident,)); c.execute('DELETE FROM buildings WHERE id=?',(ident,))
                elif kind=='team':
                    if c.execute('SELECT 1 FROM users WHERE team_id=? LIMIT 1',(ident,)).fetchone(): raise ValueError('team has personnel')
                    c.execute('DELETE FROM teams WHERE id=?',(ident,))
                elif kind=='user': c.execute('DELETE FROM assets WHERE user_id=?',(ident,)); c.execute('DELETE FROM user_buildings WHERE user_id=?',(ident,)); c.execute('DELETE FROM users WHERE id=?',(ident,))
                c.commit()
            except (ValueError, sqlite3.IntegrityError): pass
            self.redirect('/admin'); return

if __name__=='__main__':
    init(); print('AssetDesk running at http://0.0.0.0:8080'); http.server.ThreadingHTTPServer(('0.0.0.0',8080),H).serve_forever()
