# Prototype for rendering safe and alerting of Embedded Threats sent over Email

# DO NOT OPEN 'exploit.csv' IN EXCEL! 

## It is an example of the type of exploit this prototype prevents against

## I hard-coded it for my computer, but I don't gaurantee it won't post your credentials online if you open it. (Note opening it in Excel on a Windows computer will try to send the recievers SSH keys to a public-facing website. I will *not* accept any feature/pull requests that involve improving the exploit - I wrote it as an example of what *could* be sent and should not be used anywhere by anyone.

---

# Usage:

### run python scan_eml.py, follow the steps in the GUI. Note you'll need to have your email downloaded locally as a .eml file.

# Demo:

> view 'QuarterlyReportOriginal.eml' in outlook to see how it looks initially

> run python scan_eml.py, select 'QuarterlyReportOriginal.eml' in the GUI

> view 'QuarterlyReportEmail.eml' in outlook to see how the program has changed it.

---

## Exploit Details:

### This Prototype currently only works for a particular form of embedded exploits, and only in .csv format. It relies on spreadsheet programs such as Excel automatically trying to run 'formulae' in cells.
