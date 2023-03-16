# Define the URL to scrape
$url = "https://raw.githubusercontent.com/QuintenMarais/WindowsVersions/main/WindowsVersions.csv"

# Invoke the web request to get the contents of the URL
$response = Invoke-WebRequest -Uri $url

# Convert the CSV string to an array of objects
$versions = ConvertFrom-Csv -InputObject $response.Content

# Create a new array to hold the version names and major build versions
$version_info = @()

# Loop through each object in the array and extract the version name and major build version
foreach ($version in $versions) {
    $version_info += @{
        "Version Name" = $version."Version Name"
        "Major Build Version" = $version."Major Build Version"
    }
}

# Output the resulting array
$version_info
