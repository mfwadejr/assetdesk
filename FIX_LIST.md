# AssetDesk fix list

This list tracks changes to bundle into the next publish. Items remain open until verified in the running container.

## Next publish

- [x] Remove the **unit count** field from the Admin → Asset types form.
- [x] Remove the unit-count wording from the asset-type list (for example, `1 unit(s)`).
- [ ] Keep quantity selection in the employee asset entry flow using **How many?**.
- [ ] Ensure each quantity-generated asset row stays on one compact line: number, required friendly name, make, model, serial number, and asset tag.
- [ ] Verify the team **Edit** popup changes both team name and organization.
- [ ] Verify organization reassignment preserves affected people and assets.
- [ ] Audit all admin pages for the agreed compact Apple-style spacing, button sizing, and alignment.
- [ ] Verify personnel editing supports team, organization, role, and TOTP settings.
- [ ] Verify cascading admin filters for organization → team → personnel, plus search.
- [ ] Verify exports produce readable PDF and formatted Excel files.
- [ ] Increment the temporary visible version marker for the publish and record the version here.

## User and access-control revamp

- [ ] Separate a user's primary function from delegated permissions.
- [ ] Primary functions: Service Line Lead, Team Lead, and Employee.
- [ ] Add delegated Admin permission that can be granted independently of the primary function.
- [ ] Add a read-only View permission for review groups such as the PMO Office.
- [ ] Ensure every user can update their own asset information regardless of primary function.
- [ ] Ensure delegated Admin users can perform the configured administrative actions without changing their primary function.
- [ ] Ensure View users cannot create, edit, delete, rename, reassign, or otherwise modify records.
- [ ] Add a View dashboard with filter-only controls for organization, service line, team lead, team, role, and employee search.
- [ ] Apply the access rules consistently to navigation, routes, forms, and exports.

## Personnel asset review

- [ ] Replace the one-row-per-asset personnel display with one row per employee.
- [ ] Add a themed employee details popup listing all assigned assets.
- [ ] Include export from the employee popup to CSV.
- [ ] Include export from the employee popup to PDF.
- [ ] Add a clearly labeled Last updated column to the personnel list.
- [ ] Record the last update automatically after a confirmed login review, while allowing an explicit user-entered confirmation date when required.
- [ ] Show whether the last review found changes or no changes.

## Later / product decisions

- [ ] Confirm the final role hierarchy: Service Line Lead → Team Lead → Employee.
- [ ] Confirm the group hierarchy: Service Line Lead → Organization → Team.
- [ ] Remove the temporary visible version marker before the production release.

## Publish checklist

- [ ] Run Python syntax validation.
- [ ] Build the Docker image locally.
- [ ] Commit all fixes as one change set.
- [ ] Push to GitHub `main`.
- [ ] Confirm the GHCR workflow succeeds and publishes `ghcr.io/mfwadejr/assetdesk:latest`.
