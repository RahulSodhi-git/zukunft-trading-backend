$ErrorActionPreference = "Stop"

$psqlDir = "C:\Program Files\PostgreSQL\18\bin"
$createdb = Join-Path $psqlDir "createdb.exe"

if (!(Test-Path ".env")) {
  Copy-Item ".env.example" ".env"
  Write-Host "Created .env from .env.example. Edit DATABASE_URL with your PostgreSQL password, then run this again."
  exit 0
}

Write-Host "Creating database zukunft_trading if it does not already exist..."
& $createdb -h localhost -U postgres zukunft_trading
if ($LASTEXITCODE -ne 0) {
  Write-Host "If the database already exists, this is okay. Continuing migration..."
}

npm run db:migrate
Write-Host "Done. Start the API with: npm run dev"
