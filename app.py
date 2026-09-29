import base64, csv, hashlib, hmac, http.server, io, json, os, secrets, sqlite3, struct, time, urllib.parse
from http import cookies

ROOT = os.path.dirname(__file__)
DB = os.environ.get('ASSETDESK_DB', os.path.join(ROOT, 'assets.sqlite3'))
APP_VERSION = '0.0.9'
SESSIONS = {}

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys = ON'); return c

def init():
    c=db(); c.executescript('''
    CREATE TABLE IF NOT EXISTS organizations(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
    CREATE TABLE IF NOT EXISTS teams(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, organization_id INTEGER REFERENCES organizations(id));
    CREATE TABLE IF NOT EXISTS buildings(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, code TEXT NOT NULL DEFAULT '');
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'employee', team_id INTEGER REFERENCES teams(id), organization_id INTEGER REFERENCES organizations(id), mfa INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS asset_types(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, code TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, quantity INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE IF NOT EXISTS assets(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), asset_type_id INTEGER NOT NULL REFERENCES asset_types(id), has_asset INTEGER NOT NULL DEFAULT 0, make TEXT, model TEXT, serial_number TEXT, asset_tag TEXT, updated_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, asset_type_id));
    CREATE TABLE IF NOT EXISTS user_buildings(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, building_id INTEGER NOT NULL REFERENCES buildings(id) ON DELETE CASCADE, PRIMARY KEY(user_id,building_id));
    ''')
    cols=[r['name'] for r in c.execute('PRAGMA table_info(users)').fetchall()]
    if 'totp_secret' not in cols: c.execute('ALTER TABLE users ADD COLUMN totp_secret TEXT')
    if 'organization_id' not in cols: c.execute('ALTER TABLE users ADD COLUMN organization_id INTEGER REFERENCES organizations(id)')
    tcols=[r['name'] for r in c.execute('PRAGMA table_info(teams)').fetchall()]
    if 'organization_id' not in tcols: c.execute('ALTER TABLE teams ADD COLUMN organization_id INTEGER REFERENCES organizations(id)')
    acols=[r['name'] for r in c.execute('PRAGMA table_info(asset_types)').fetchall()]
    if 'quantity' not in acols: c.execute('ALTER TABLE asset_types ADD COLUMN quantity INTEGER NOT NULL DEFAULT 1')
    xcols=[r['name'] for r in c.execute('PRAGMA table_info(assets)').fetchall()]
    if 'instances_json' not in xcols: c.execute('ALTER TABLE assets ADD COLUMN instances_json TEXT NOT NULL DEFAULT "[]"')
    if c.execute('SELECT COUNT(*) n FROM organizations').fetchone()['n']==0: c.execute('INSERT INTO organizations(name) VALUES(?)',('Default Organization',))
    if c.execute('SELECT COUNT(*) n FROM teams').fetchone()['n']==0: c.executemany('INSERT INTO teams(name,organization_id) VALUES(?,1)',[('Operations',),('Engineering',),('Finance',),('People & Culture',)])
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
    return f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)} · AssetDesk</title><link rel="stylesheet" href="/static/style.css"></head><body><header><a class="brand" href="/">ASSET<span>DESK</span><small>v{APP_VERSION}</small></a><nav>{admin}{nav}</nav></header><main>{body}</main></body></html>'''

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
        if path=='/admin' and u['role'] in ('admin','lead','service_lead'):
            query=urllib.parse.parse_qs(p.query); team_filter=query.get('team',[''])[0]; employee_filter=query.get('employee',[''])[0]; search=query.get('q',[''])[0].strip(); teams=c.execute('SELECT * FROM teams ORDER BY name').fetchall(); employees=c.execute('SELECT id,name,team_id FROM users ORDER BY name').fetchall(); where=''; args=[]
            person_team=query.get('person_team',[''])[0]; person_role=query.get('person_role',[''])[0]; person_q=query.get('person_q',[''])[0].strip(); person_where=[]; person_args=[]
            if person_team: person_where.append('u.team_id=?'); person_args.append(person_team)
            if person_role: person_where.append('u.role=?'); person_args.append(person_role)
            if person_q: person_where.append('(u.name LIKE ? OR u.email LIKE ?)'); person_args += [f'%{person_q}%',f'%{person_q}%']
            people_rows=c.execute('SELECT u.*,t.name team_name FROM users u LEFT JOIN teams t ON t.id=u.team_id '+(('WHERE '+' AND '.join(person_where)) if person_where else '')+' ORDER BY u.name',person_args).fetchall()
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
                org_rows=c.execute('SELECT * FROM organizations ORDER BY name').fetchall()
                orgs='<section class="panel admin-panel"><h2>Organizations</h2><form method="post" action="/admin/organization" class="inlineform"><input name="name" placeholder="Organization name" required><button>Add organization</button></form><div class="chips">'+''.join(f'<span><b>{esc(o["name"])}</b><form method="post" action="/admin/delete/organization/{o["id"]}" class="inlineform"><select name="replacement"><option value="">Delete only if empty</option>'+''.join(f'<option value="{z["id"]}">Reassign to {esc(z["name"])}</option>' for z in org_rows if z["id"]!=o["id"])+'</select><button class="chip-delete">Delete</button></form></span>' for o in org_rows)+'</div></section>'
                asset_types='<section class="panel admin-panel"><h2>Asset types</h2><form method="post" action="/admin/type" class="inlineform"><input name="name" placeholder="e.g. Monitor" required><input name="code" placeholder="Code" required><input name="quantity" type="number" min="1" value="1" title="Number of units"><button>Add asset type</button></form><div class="chips">'+''.join(f'<span>{esc(a["name"])} · {a["quantity"]} unit(s) <button class="chip-delete" form="del-a{a["id"]}">×</button></span><form id="del-a{a["id"]}" method="post" action="/admin/delete/asset-type/{a["id"]}" onsubmit="return confirm("Delete this asset type and its records?")"></form>' for a in c.execute('SELECT * FROM asset_types ORDER BY name'))+'</div></section>'
                team_list='<section class="panel admin-panel"><h2>Teams</h2><form method="post" action="/admin/team" class="inlineform"><input name="name" placeholder="Team name" required><select name="organization_id" required><option value="">Organization</option>'+''.join(f'<option value="{o["id"]}">{esc(o["name"])}</option>' for o in c.execute('SELECT * FROM organizations ORDER BY name'))+'</select><button>Add team</button></form><div class="chips">'+''.join(f'<span><b>{esc(t["name"])}</b><small>{esc(c.execute("SELECT name FROM organizations WHERE id=?",(t["organization_id"],)).fetchone()["name"] if t["organization_id"] else "No organization")}</small><button type="button" class="button secondary rename-trigger" data-id="{t["id"]}" data-name="{esc(t["name"])}">Rename</button><form method="post" action="/admin/delete/team/{t["id"]}" class="inlineform"><select name="replacement"><option value="">Delete only if empty</option>'+''.join(f'<option value="{z["id"]}">Reassign to {esc(z["name"])}</option>' for z in teams if z["id"]!=t["id"])+'</select><button class="chip-delete">Delete</button></form></span>' for t in teams)+'</div><dialog id="renameDialog"><form method="post" id="renameForm"><h3>Rename team</h3><input name="name" id="renameName" required><div class="dialog-actions"><button type="button" class="secondary" onclick="renameDialog.close()">Cancel</button><button>Save</button></div></form></dialog><script>document.querySelectorAll(".rename-trigger").forEach(b=>b.onclick=()=>{renameName.value=b.dataset.name;renameForm.action="/admin/team/rename/"+b.dataset.id;renameDialog.showModal();});</script></section>'
                building_list='<section class="panel admin-panel"><h2>Buildings</h2><form method="post" action="/admin/building" class="inlineform"><input name="name" placeholder="Building name" required><input name="code" placeholder="Code"><button>Add building</button></form><div class="chips">'+''.join(f'<span>{esc(b["name"])} <small>{esc(b["code"])}</small> <button class="chip-delete" form="del-b{b["id"]}">×</button></span><form id="del-b{b["id"]}" method="post" action="/admin/delete/building/{b["id"]}" onsubmit="return confirm("Delete this building?")"></form>' for b in c.execute('SELECT * FROM buildings ORDER BY name'))+'</div></section>'
                person_rows=''.join(f'<tr><td>{esc(p["name"])}</td><td>{esc(p["email"])}</td><td>{esc(p["team_name"] or "No team")}</td><td>{esc(p["role"].title())}</td><td><a class="button secondary" href="/admin/user/edit?id={p["id"]}">Edit</a> <button class="chip-delete" form="del-p{p["id"]}">Delete</button><form id="del-p{p["id"]}" method="post" action="/admin/delete/user/{p["id"]}" onsubmit="return confirm("Delete this person and their asset records?")"></form></td></tr>' for p in people_rows)
                person_body=person_rows or '<tr><td colspan="5" class="empty">No matching people.</td></tr>'
                people='<section class="panel admin-panel"><h2>Personnel directory</h2><form class="filters" method="get"><input type="hidden" name="team" value="'+esc(team_filter)+'"><label>Assigned team<select name="person_team"><option value="">All teams</option>'+''.join(f'<option value="{t["id"]}" {"selected" if str(t["id"])==person_team else ""}>{esc(t["name"])}</option>' for t in teams)+'</select></label><label>Role<select name="person_role"><option value="">All roles</option><option value="admin">Admin</option><option value="lead">Team Lead</option><option value="employee">Employee</option></select></label><label>Search<input name="person_q" value="'+esc(person_q)+'" placeholder="Name or email"></label><button>Filter</button></form><form method="post" action="/admin/user" class="inlineform"><input name="name" placeholder="Full name" required><input name="email" type="email" placeholder="Email" required><input name="password" placeholder="Temporary password" required><select name="team_id">'+''.join(f'<option value="{t["id"]}">{esc(t["name"])}</option>' for t in teams)+'</select><select name="role"><option value="employee">Employee</option><option value="lead">Team Lead</option><option value="admin">Admin</option></select><button>Add person</button></form><div class="tablewrap"><table><thead><tr><th>Name</th><th>Email</th><th>Assigned team</th><th>Role</th><th></th></tr></thead><tbody>'+person_body+'</tbody></table></div></section>'
                org_options=''.join(f'<option value="{o["id"]}">{esc(o["name"])}</option>' for o in c.execute('SELECT * FROM organizations ORDER BY name'))
                body += orgs+asset_types+team_list+building_list+people+'<script>document.querySelectorAll("select[name=role],select[name=person_role]").forEach(s=>{if(![...s.options].some(o=>o.value==="service_lead")){let o=document.createElement("option");o.value="service_lead";o.textContent="Service Line Lead";s.appendChild(o);}});document.querySelectorAll(".rename-trigger").forEach(b=>{b.textContent="Edit";b.onclick=()=>{renameName.value=b.dataset.name;let old=document.getElementById("renameOrg");if(old)old.remove();let s=document.createElement("select");s.id="renameOrg";s.name="organization_id";s.innerHTML="'+org_options+'";s.value=b.dataset.org||"";renameForm.insertBefore(s,renameForm.querySelector(".dialog-actions"));renameForm.action="/admin/team/update/"+b.dataset.id;renameDialog.showModal();};});</script>'
            self.send(page('Admin',body,u)); return
        if path=='/admin/user/edit' and u['role']=='admin':
            target=c.execute('SELECT * FROM users WHERE id=?',(urllib.parse.parse_qs(p.query).get('id',[''])[0],)).fetchone()
            if not target: self.redirect('/admin'); return
            teams=c.execute('SELECT * FROM teams ORDER BY name').fetchall()
            body=f'<section class="auth"><div class="eyebrow">ADMINISTRATION</div><h1>Edit personnel</h1><form method="post" action="/admin/user/update"><input type="hidden" name="id" value="{target["id"]}"><label>Name<input name="name" value="{esc(target["name"])}" required></label><label>Email<input name="email" type="email" value="{esc(target["email"])}" required></label><label>Assigned team<select name="team_id">'+''.join(f'<option value="{t["id"]}" {"selected" if t["id"]==target["team_id"] else ""}>{esc(t["name"])}</option>' for t in teams)+'</select></label><label>Role<select name="role"><option value="employee" {"selected" if target["role"]=="employee" else ""}>Employee</option><option value="lead" {"selected" if target["role"]=="lead" else ""}>Team Lead</option><option value="admin" {"selected" if target["role"]=="admin" else ""}>Admin</option></select></label><label>New password (optional)<input name="password" type="password" placeholder="Leave blank to keep current"></label><button>Save changes</button><a class="button secondary" href="/admin">Cancel</a></form></section>'
            self.send(page('Edit personnel',body,u)); return
        types=c.execute('SELECT * FROM asset_types WHERE active=1 ORDER BY id').fetchall(); existing={r['asset_type_id']:r for r in c.execute('SELECT * FROM assets WHERE user_id=?',(u['id'],))}; team=c.execute('SELECT name FROM teams WHERE id=?',(u['team_id'],)).fetchone()['name']; buildings=c.execute('SELECT * FROM buildings ORDER BY name').fetchall(); selected_buildings={r['building_id'] for r in c.execute('SELECT building_id FROM user_buildings WHERE user_id=?',(u['id'],))}; cards=''
        for a in types:
            x=existing.get(a['id']); yes=x and x['has_asset']; instances=json.loads(x['instances_json'] or '[]') if x and x['instances_json'] else [{}]; inst=instances[0] if instances else {}; details='<div class="details" style="display:'+('block' if yes else 'none')+'"><label class="quantity">How many? <input type="number" min="1" max="20" name="count_'+str(a['id'])+'" value="'+str(max(1,len(instances)))+'" oninput="resizeInstances(this)"></label><div class="instances">'+f'<div class="instance"><strong class="instance-number">1.</strong><input required name="friendly_{a["id"]}_0" placeholder="Friendly name" value="{esc(inst.get("friendly",""))}"><input name="make_{a["id"]}_0" placeholder="Make" value="{esc(inst.get("make",""))}"><input name="model_{a["id"]}_0" placeholder="Model" value="{esc(inst.get("model",""))}"><input name="serial_{a["id"]}_0" placeholder="Serial number" value="{esc(inst.get("serial",""))}"><input name="tag_{a["id"]}_0" placeholder="Asset tag" value="{esc(inst.get("tag",""))}"></div></div></div>'
            cards+=f'<article class="assetcard"><div><h3>{esc(a["name"])}</h3><p class="muted">Do you have this asset assigned to you?</p></div><div class="answer"><label><input type="radio" name="has_{a["id"]}" value="1" {"checked" if yes else ""} onchange="toggleDetails(this)"> Yes</label><label><input type="radio" name="has_{a["id"]}" value="0" {"checked" if not yes else ""} onchange="toggleDetails(this)"> No</label></div>{details}</article>'
        building_form='<section class="panel building-select"><h2>Building access</h2><p class="muted">Select the buildings this employee is authorized to access.</p><div class="building-options">'+''.join(f'<label><input type="checkbox" name="building" value="{b["id"]}" {"checked" if b["id"] in selected_buildings else ""}> {esc(b["name"])} <small>{esc(b["code"])}</small></label>' for b in buildings)+'</div></section>'
        body=f'<div class="pagehead"><div><div class="eyebrow">{esc(team).upper()} TEAM</div><h1>Your asset check-in</h1><p class="muted">Answer each question. Add identifying details when you have the asset.</p></div><span class="status">Autosave is off · submit when ready</span></div><form method="post" action="/save">{building_form}<div class="assetgrid">{cards}</div><button class="save">Save asset record</button></form><script>function toggleDetails(el){{let card=el.closest(".assetcard"),d=card.querySelector(".details");if(d)d.style.display=el.value=="1"?"block":"none";}}function resizeInstances(input){{let card=input.closest(".assetcard"),wrap=card.querySelector(".instances"),n=Math.max(1,Math.min(20,parseInt(input.value||1)));while(wrap.children.length<n){{let i=wrap.children.length,source=wrap.children[0].cloneNode(true);source.querySelector(".instance-number").textContent=(i+1)+".";source.querySelectorAll("input").forEach(x=>{{x.value="";x.name=x.name.replace(/_\\d+$/, "_"+i);}});wrap.appendChild(source);}}while(wrap.children.length>n)wrap.removeChild(wrap.lastChild);}}</script>'
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
                has=int(f.get(f'has_{a["id"]}',['0'])[0]); instances=[]
                for i in range(max(1,min(20,int(f.get(f'count_{a["id"]}',['1'])[0])))): instances.append({'friendly':f.get(f'friendly_{a["id"]}_{i}',[''])[0],'make':f.get(f'make_{a["id"]}_{i}',[''])[0],'model':f.get(f'model_{a["id"]}_{i}',[''])[0],'serial':f.get(f'serial_{a["id"]}_{i}',[''])[0],'tag':f.get(f'tag_{a["id"]}_{i}',[''])[0]})
                vals=(u['id'],a['id'],has,instances[0]['make'],instances[0]['model'],instances[0]['serial'],instances[0]['tag'],json.dumps(instances)); c.execute('''INSERT INTO assets(user_id,asset_type_id,has_asset,make,model,serial_number,asset_tag,instances_json) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(user_id,asset_type_id) DO UPDATE SET has_asset=excluded.has_asset,make=excluded.make,model=excluded.model,serial_number=excluded.serial_number,asset_tag=excluded.asset_tag,instances_json=excluded.instances_json,updated_at=CURRENT_TIMESTAMP''',vals)
            c.commit(); self.send(page('Saved','<section class="success"><div class="eyebrow">RECORD SAVED</div><h1>Thanks — your assets are up to date.</h1><p class="muted">Your team lead can now see the latest details in the register.</p><a class="button" href="/">Back to my assets</a></section>',u)); return
        if path=='/admin/type' and u['role']=='admin':
            try: c.execute('INSERT INTO asset_types(name,code,quantity) VALUES(?,?,?)',(f.get('name',[''])[0],f.get('code',[''])[0].upper(),max(1,int(f.get('quantity',['1'])[0])))); c.commit()
            except sqlite3.IntegrityError: pass
            self.redirect('/admin'); return
        if path=='/admin/team' and u['role']=='admin':
            try: c.execute('INSERT INTO teams(name,organization_id) VALUES(?,?)',(f.get('name',[''])[0],f.get('organization_id',[''])[0] or None)); c.commit()
            except sqlite3.IntegrityError: pass
            self.redirect('/admin'); return
        if path=='/admin/organization' and u['role']=='admin':
            try: c.execute('INSERT INTO organizations(name) VALUES(?)',(f.get('name',[''])[0],)); c.commit()
            except sqlite3.IntegrityError: pass
            self.redirect('/admin'); return
        if path.startswith('/admin/team/rename/') and u['role']=='admin':
            try: c.execute('UPDATE teams SET name=? WHERE id=?',(f.get('name',[''])[0],int(path.rsplit('/',1)[-1]))); c.commit()
            except sqlite3.IntegrityError: pass
            self.redirect('/admin'); return
        if path.startswith('/admin/team/update/') and u['role']=='admin':
            try: c.execute('UPDATE teams SET name=?,organization_id=? WHERE id=?',(f.get('name',[''])[0],f.get('organization_id',[''])[0] or None,int(path.rsplit('/',1)[-1]))); c.commit()
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
        if path=='/admin/user/update' and u['role']=='admin':
            uid=f.get('id',[''])[0]; pw=f.get('password',[''])[0]
            if pw: c.execute('UPDATE users SET name=?,email=?,team_id=?,role=?,password=? WHERE id=?',(f.get('name',[''])[0],f.get('email',[''])[0].lower(),f.get('team_id',[None])[0],f.get('role',['employee'])[0],hashlib.sha256(pw.encode()).hexdigest(),uid))
            else: c.execute('UPDATE users SET name=?,email=?,team_id=?,role=? WHERE id=?',(f.get('name',[''])[0],f.get('email',[''])[0].lower(),f.get('team_id',[None])[0],f.get('role',['employee'])[0],uid))
            c.commit(); self.redirect('/admin'); return
        if path.startswith('/admin/delete/') and u['role']=='admin':
            kind, ident = path.split('/')[-2:]
            try:
                ident=int(ident)
                if kind=='asset-type': c.execute('DELETE FROM assets WHERE asset_type_id=?',(ident,)); c.execute('DELETE FROM asset_types WHERE id=?',(ident,))
                elif kind=='building': c.execute('DELETE FROM user_buildings WHERE building_id=?',(ident,)); c.execute('DELETE FROM buildings WHERE id=?',(ident,))
                elif kind=='organization':
                    replacement=f.get('replacement',[''])[0]
                    if replacement: c.execute('UPDATE teams SET organization_id=? WHERE organization_id=?',(int(replacement),ident)); c.execute('UPDATE users SET organization_id=? WHERE organization_id=?',(int(replacement),ident))
                    elif c.execute('SELECT 1 FROM teams WHERE organization_id=? LIMIT 1',(ident,)).fetchone() or c.execute('SELECT 1 FROM users WHERE organization_id=? LIMIT 1',(ident,)).fetchone(): raise ValueError('organization has records')
                    c.execute('DELETE FROM organizations WHERE id=?',(ident,))
                elif kind=='team':
                    replacement=f.get('replacement',[''])[0]
                    if replacement: c.execute('UPDATE users SET team_id=? WHERE team_id=?',(int(replacement),ident))
                    elif c.execute('SELECT 1 FROM users WHERE team_id=? LIMIT 1',(ident,)).fetchone(): raise ValueError('team has personnel')
                    c.execute('DELETE FROM teams WHERE id=?',(ident,))
                elif kind=='user': c.execute('DELETE FROM assets WHERE user_id=?',(ident,)); c.execute('DELETE FROM user_buildings WHERE user_id=?',(ident,)); c.execute('DELETE FROM users WHERE id=?',(ident,))
                c.commit()
            except (ValueError, sqlite3.IntegrityError): pass
            self.redirect('/admin'); return

if __name__=='__main__':
    init(); print('AssetDesk running at http://0.0.0.0:8080'); http.server.ThreadingHTTPServer(('0.0.0.0',8080),H).serve_forever()
