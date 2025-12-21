# AutomationZ Admin Orchestrator 👑 [![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R6R51QD7BU)

Central automation and deployment toolkit for Game servers / websites etc.

---

## What is this?

AutomationZ Admin Orchestrator is the **core control system** of the AutomationZ ecosystem.

It allows server administrators to:

- Deploy configuration presets safely
- Apply changes to multiple servers or local installs
- Group files into reusable mappings
- Combine mappings into mapping sets
- Execute deployments via plans
- Run plans manually or on schedules
- Restart servers (RCON or Nitrado API)
- Verify applied changes
- Keep full logs and backups
- Receive Discord notifications

This tool replaces manual FTP work with **repeatable, auditable automation**.

---

## Core Concepts (Important)

- **Preset** → Folder containing source files
- **Mapping** → One file copy rule
- **Mapping Set** → Group of mappings
- **Plan** → Execution recipe
- **Profile** → Target server or local install

---

## Application Tabs

- Dashboard
- Profiles
- Mappings
- Mapping Sets
- Plans & Schedule
- Settings
- Help
- Log panel (always visible)

Each tab is documented in separate README files below.

# Dashboard
[![Orchestrator_Dashboard.png](https://i.postimg.cc/VvT7DgCW/Orchestrator_Dashboard.png)](https://postimg.cc/WqG64MSd)
The Dashboard is the main control screen.

---

## Features

### Plan Selector
Select which plan to run or monitor.

### Run Plan Now
Immediately executes the selected plan.
Ignores scheduler timing.

### Start Scheduler
Starts or stops the internal scheduler.
The scheduler checks every **Tick seconds**.

---

## Next / Status Panel

Shows:
- Presets folder location
- Scheduler state (RUNNING / STOPPED)
- Current date and time
- All scheduled plans:
  - Name
  - Time
  - Days
  - Restart mode

---

## Quick Access Buttons

- Open Presets
- Open Backups
- Open Logs

---

## Typical Use

- Monitor scheduled automation
- Verify timing and configuration
- Trigger plans manually when needed

# Profiles
[![Orchestrator_profiles.png](https://i.postimg.cc/C5tvm7qH/Orchestrator_profiles.png)](https://postimg.cc/bSxHvQLs)
A Profile represents **one target environment**.

---

## Supported Types

- FTP / FTPS server
- Local server (Local Mode)

---

## Fields Explained

### Name
Logical name used in plans.

### FTP Host / Port / Username / Password
Remote server connection details.

### Use FTPS (TLS)
Enables encrypted FTP.

### Remote Root
Base directory on the server.
Example:
`/dayzstandalone`

---

## Local Mode (no FTP)

When enabled:
- FTP is bypassed
- Files are copied directly to a local folder

### Local Root Folder
Target directory for Local Mode.

Used for:
- Home servers
- Testing
- Development environments

---

## RCON (optional)

Used when plan restart mode = `rcon`.

- RCON Host
- RCON Port
- RCON Password

Note:
Some hosts (e.g. Nitrado) do not expose RCON passwords.

---

## Nitrado API (optional)

Used when restart mode = `nitrado`.

- Nitrado Service ID
- Nitrado Lifelong Token

---

## Buttons

- New
- Delete
- Save Changes

# Mappings
[![Orchestrator_Mappings.png](https://i.postimg.cc/nr5d02DK/Orchestrator_Mappings.png)](https://postimg.cc/D4rdzq5m)
A Mapping defines **one file deployment rule**.

---

## Structure

Preset file → Destination path

---

## Fields

### Name
Logical mapping name.

### Local relpath (inside preset)
Relative path inside the preset folder.

Example:
`BBP_raid_on.json`

### Remote path
Destination path relative to:
- FTP root
- OR local root (Local Mode)

Example:
`config/BaseBuildingPlus/BBP_Settings.json`

### Backup before overwrite
If enabled:
- Existing file is backed up
- Stored in:
  `backups/<profile>/<plan>/<timestamp>/`

---

## Purpose

Mappings are reusable building blocks.
They are combined into Mapping Sets.

# Mapping Sets
[![Orchestrator_Mapping_sets.png](https://i.postimg.cc/Xqh2QLCw/Orchestrator_Mapping_sets.png)](https://postimg.cc/GTFJpkz2)
A Mapping Set is a **collection of mappings**.

---

## Why Mapping Sets?

Instead of selecting individual files in a plan,
you select **one logical set**.

Examples:
- Raids ON
- Raids OFF
- Winter Weather
- DZB Loadout Sunday

---

## Interface

### Left Panel
List of all mapping sets.

### Right Panel

#### Set Name
Editable name of the set.

#### Mappings Included
Checkbox list of all available mappings.

---

## Buttons

- New
- Delete (Default set cannot be deleted)
- Save Changes

---

## Best Practice

One Mapping Set = one gameplay concept.

# Plans & Schedule
[![Orchestrator_Plans_Schedule.png](https://i.postimg.cc/BbyhMpK2/Orchestrator_Plans_Schedule.png)](https://postimg.cc/vxrLmWXm)
A Plan defines **how, where, and when** changes are applied.

---

## Core Fields

### Name
Plan identifier.

### Enabled
Disabled plans are ignored.

### Targets
Comma-separated profile names.

Example:
`The Long Hunt, Test Server`

### Preset Folder
Folder inside `presets/`.

### Mapping Set
Which mappings are applied.

---

## Restart Options

### Restart Mode
- none
- rcon
- nitrado

### RCON Command
Used when restart mode = rcon.
Default:
`#shutdown`

### Nitrado Restart Message
Shown in Nitrado UI and server message.

---

## Verification (FTP only)

### Verify Mode
- none
- contains
- not_contains

### Verify Remote Path
File to download after deployment.

### Verify Keywords
Comma-separated keywords.

Used to confirm successful changes.

---

## Scheduling

### Enable Schedule
Turns on automatic execution.

### Time
24-hour format.

### Days
Select which days the plan runs.

---

## Notes

Scheduler runs in-process.
Plans will not run twice in the same minute.

# Settings
[![Orchestrator_Settings.png](https://i.postimg.cc/D0DCB6XL/Orchestrator_Settings.png)](https://postimg.cc/GTFJpkzm)
---

## App Settings

### Timeout seconds
FTP / API timeout.

### Tick seconds
Scheduler polling interval.

### Host type
- dedicated
- nitrado

### Presets folder override
Use a custom presets directory.

Useful for synced folders or external drives.

---

## Discord Webhook
[![Orchestrator_Discord.png](https://i.postimg.cc/SNyXQ9JR/Orchestrator_Discord.png)](https://postimg.cc/QVyN0HgZ)
### Webhook URL
Discord Incoming Webhook URL.

### Username
Displayed sender name.

### Notify options
- Notify start
- Notify success
- Notify failure

---

## Buttons

- Save Settings
- Test Discord

---

## Notes

Settings are saved to:
`config/settings.json`

## Credits

---
🧩 Part of AutomationZ Control Center
This tool is part of the AutomationZ Admin Toolkit:

- AutomationZ Uploader
- AutomationZ Scheduler
- AutomationZ Server Backup Scheduler
- AutomationZ Server Health
- AutomationZ Config Diff
- AutomationZ Admin Orchestrator
- AutomationZ Log Cleanup Scheduler

Together they form a complete server administration solution.

### 💚 Support the project

AutomationZ tools are built for server owners by a server owner.  
If these tools save you time or help your community, consider supporting development.

☕ Ko-fi: https://ko-fi.com/dannyvandenbrande  
💬 Discord: https://discord.gg/6g8EPES3BP  

Created by **Danny van den Brande**  
DayZ AutomationZ
☕ Ko-fi: https://ko-fi.com/dannyvandenbrande  
💬 Discord: https://discord.gg/6g8EPES3BP  

Created by **Danny van den Brande**  
DayZ AutomationZ
