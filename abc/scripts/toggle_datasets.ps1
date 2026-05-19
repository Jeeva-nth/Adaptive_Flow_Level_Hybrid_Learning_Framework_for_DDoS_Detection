param (
    [switch]$Enable
)

$balanced_dir = "ddos_balanced"
$imbalanced_dir = "ddos_imbalanced"

if ($Enable) {
    Write-Host "Enabling datasets (renaming .csv.offline to .csv)..."
    if (Test-Path "$balanced_dir\final_dataset.csv.offline") {
        Rename-Item "$balanced_dir\final_dataset.csv.offline" "final_dataset.csv"
        Write-Host "Enabled $balanced_dir\final_dataset.csv"
    }
    if (Test-Path "$imbalanced_dir\unbalaced_20_80_dataset.csv.offline") {
        Rename-Item "$imbalanced_dir\unbalaced_20_80_dataset.csv.offline" "unbalaced_20_80_dataset.csv"
        Write-Host "Enabled $imbalanced_dir\unbalaced_20_80_dataset.csv"
    }
    Write-Host "Datasets are ready to use."
} else {
    Write-Host "Temporarily shutting down datasets (renaming .csv to .csv.offline)..."
    if (Test-Path "$balanced_dir\final_dataset.csv") {
        Rename-Item "$balanced_dir\final_dataset.csv" "final_dataset.csv.offline"
        Write-Host "Disabled $balanced_dir\final_dataset.csv"
    }
    if (Test-Path "$imbalanced_dir\unbalaced_20_80_dataset.csv") {
        Rename-Item "$imbalanced_dir\unbalaced_20_80_dataset.csv" "unbalaced_20_80_dataset.csv.offline"
        Write-Host "Disabled $imbalanced_dir\unbalaced_20_80_dataset.csv"
    }
    Write-Host "Datasets have been shut down safely. Run with -Enable to restore."
}
