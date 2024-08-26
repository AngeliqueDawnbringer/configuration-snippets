# https://learn.microsoft.com/en-us/purview/sensitivity-labels-office-apps#prevent-some-connected-experiences-that-analyze-content
# Use at least ExOM 3.4
Install-Module -Name ExchangeOnlineManagement
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
Import-Module ExchangeOnlineManagement
Connect-IPPSSession

# Get All Labels
Get-Label

# I have 5 labels. C1-C4 and Custom

# Show All Properties of a Label in a List
# Get-Label -Identity "Custom" | Format-List

# Show the Label-Settings Only
(Get-Label -Identity "Custom").Settings

# Prevent Content Analysis online from Connected Experiences and Microsoft 364 CoPilot
Set-Label -Identity "Custom" -AdvancedSettings @{BlockContentAnalysisServices="True"}

(Get-Label -Identity "Custom").Settings

# Lock down the system again
Set-ExecutionPolicy -ExecutionPolicy Restricted