# Push-trigger audit fixture

This is a second, independent synthetic fixture for testing a push to master after enabling the repository trigger. All credential values are explicitly fake, the database uses a reserved .invalid domain, and the application never loads these files. Empty and placeholder values in .env.example are negative controls.

Check the push event, automation execution, selected target SHA, incremental baseline, changed-file coverage, and finding identity. Synthetic dismissal is acceptable; these files are not evidence of live credential exposure.
