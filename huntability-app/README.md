# Huntability Assessment — Azure Static Web App

## Overview

A self-service tool for assessing an organization's readiness to perform cloud threat hunts across the VBD module domains. Outputs a huntability score per attack category with gap analysis.

## Deployment

### Azure Static Web Apps (recommended)

```bash
az staticwebapp create \
  --name huntability-assessment \
  --resource-group <rg-name> \
  --source https://github.com/<org>/cloud-threat-hunting-vbd \
  --location "eastus2" \
  --branch main \
  --app-location "/huntability-app/public" \
  --output-location "" \
  --login-with-github
```

### Local Development

```bash
cd huntability-app/public
npx serve .
```

Open `http://localhost:3000` in a browser.

## How It Works

1. User checks off which log sources are enabled in their Sentinel workspace
2. User checks off which security controls are implemented
3. App calculates a weighted huntability score per attack category
4. Overall grade (A–F) with gap analysis

## Scoring Model

- **Log Coverage** (60% weight): Are the required Sentinel tables receiving data?
- **Control Coverage** (40% weight): Are the preventive/detective controls in place?

Each log source and control has an importance weight within its category, reflecting how critical it is for hunting that specific attack type.

## Customization

Edit `src/data/scoring-rubric.json` to:
- Add new attack categories
- Adjust weights
- Add/remove log sources or controls
- Modify grade thresholds
