<#.SYNOPSIS
    This Powershell script will report on the security Posture of the AD that it is running in.
.EXAMPLE
    .\Detect-Appinstalled.ps1
.DESCRIPTION
    This script will query all AD accounts and test it against rules specified in the script below to detirmine the securiy posture of that account. It will then export all the information to a CSV file in the same folder.
.TO DO
    - Enable Mailing
    - Declare variables at the beginnin of the script
    - Change Colomn L and N to say never logged / Never Set
    - Add Customer details in mail
    - Add Server details that is sending the mail.

.Versions

    1.1         Added the SEP=, to the beginning of the file for easier usage of the file
    1.2         Error found in details between 66080 and 66084
    1.3         Fixing some formating and variables
                Add logic for the script to check the password age on its own 
    1.4         Splitting out settings to its own ini file
    
.NOTES
    Version:        1.4
    Creation Date:  2022/12/19
    Last Updated:   2023/02/07
    Author:         Quinten Marais
    Organization:   Logicalis
    Contact:        Quinten.Marais@za.logicalis.com
    Web Site:       None
#>
###########################################################################################
#Creating a Safe Space and Finding myself
###########################################################################################

Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force -ErrorAction 'Stop' } Catch {}
# Triangulating 
If (Test-Path -LiteralPath 'variable:HostInvocation') { $InvocationInfo = $HostInvocation } Else { $InvocationInfo = $MyInvocation }
    [string]$scriptDirectory = Split-Path -Path $InvocationInfo.MyCommand.Definition -Parent

###########################################################################################
#Defining and adding additional external functions
###########################################################################################

#Adding ini Parsing function
. "$scriptDirectory\supportfiles\importini.ps1"

#Adding Logging Module
. "$scriptDirectory\supportfiles\WriteLog.ps1"

###########################################################################################
#Read some Settings from the INI
###########################################################################################

$settings = getinfofonini("$scriptDirectory\settings\settings.ini")

###########################################################################################
#Setting Script Details
###########################################################################################
$ScriptVersion          = $settings["UserReport"]["Version"]
$ScriptCustomer         = $settings["Customer"]["CustomerName"]
$ScriptServer           = $env:computername


$EmailAlerts            = $settings["UserReport"]["EmailAlerts"]
$Emailto                = $settings["MailSettings"]["Emailto"]
$EmailFrom              = $settings["MailSettings"]["EmailFrom"]
$EmailFromNice          = $settings["MailSettings"]["EmailFromNice"]
$EmailUsername          = $settings["MailSettings"]["EmailUsername"]
$EmailPlusAddr          = $settings["MailSettings"]["EmailPlusAddr"]
$EmailPassword          = $settings["MailSettings"]["EmailPassword"]
$EmailServer            = $settings["MailSettings"]["EmailServer"]
$EmailPort              = $settings["MailSettings"]["EmailPort"]
$OverridePasswordAge    = $settings["UserReport"]["OverridePasswordAge"]

###########################################################################################
#Configure
###########################################################################################
$Progress = "Preparing"

#Configuring Logging Module to log to the script Location\Logs
$Filedate           = Get-Date -Format "yyyyddMM"
$WeekNumber         = get-date -UFormat %V
$StartDate          = (GET-DATE)
$LogCycle           = $settings["UserReport"]["LogCycle"]
$Trimmedcustomer    = $ScriptCustomer.replace(" ","")
$LogFilename        = $scriptDirectory +"\Logs\" + $settings["UserReport"]["FileName"] +"_"+ $(Get-Date -Format yyyy-M-dd) + ".log"
$Filename           = $scriptDirectory +"\Output\" + $settings["UserReport"]["FileName"] +"_"+ $(Get-Date -Format yyyy-M-dd) + ".csv"
$SMTPUsername       = $EmailUSername
$SMTPPassw          = ConvertTo-SecureString $EmailUSername  -AsPlainText -Force
$Cred               = New-Object System.Management.Automation.PSCredential ($SMTPUsername, $SMTPPassw)

# Building Out the Mail Details
$mailParams = @{
    SmtpServer                 = $EmailServer 
    Port                       = $EmailPort 
    Credential                 = $Cred
    From                       = new-object System.Net.Mail.MailAddress($EmailFrom, $EmailFromNice)
    To                         = $Emailto  
    Subject                    = $Customer+' Weekly User Account Report Week '+$WeekNumber
    Body                       = "Customer : $ScriptCustomer`r`nScript Server : $ScriptServer`r`nScript Location : $scriptDirectory`r`nScript version : v$ScriptVersion`r`n`r`nWeekly User Account Report Week $WeekNumber"
    Attachment                 = $Filename
}
###########################################################################################
#Get Default Domain Password Policy - Max Password Age
###########################################################################################
    Write-Log -Path $LogFilename -Message "Script Version : v$ScriptVersion" -Component $Progress  -Type Info
    Write-Log -Path $LogFilename -Message "Customer Name  : $ScriptCustomer" -Component $Progress  -Type Info
    Write-Log -Path $LogFilename -Message "Server Running Script : $ScriptServer" -Component $Progress  -Type Info
    Write-Log -Path $LogFilename -Message "Email from : $Emailto " -Component $Progress  -Type Info
    Write-Log -Path $LogFilename -Message "Email from Nice Set to : $emailfromnice " -Component $Progress  -Type Info
if ($EmailAlerts -eq $True )
    {
    Write-Log -Path $LogFilename -Message "Email to : $Emailto" -Component $Progress  -Type Warning
    }
    else
    {
    Write-Log -Path $LogFilename -Message "Email to : $Emailto" -Component $Progress  -Type Info
    }


if ($OverridePasswordAge -eq $True )
    {
        Write-Log -Path $LogFilePath -Message "AD Expiry is Set to $OverridePasswordAge Days" -Component $Progress  -Type Warning
        $MaxPasswordAge = $OverridePasswordAge
    }
    else
    {
        Write-Log -Path $LogFilename -Message "Using the Password Age set in Active Directory." -Component $Progress  -Type Info

        $passwordage = get-ADDefaultDomainPasswordPolicy
        $MaxPasswordAge = $passwordage.MaxPasswordAge.days
        Write-Log -Path $LogFilename -Message "Setting the Password Age : get-ADDefaultDomainPasswordPolicy returned a value of $MaxPasswordAge Days" -Component $Progress  -Type Info
    }


###########################################################################################
#          Let the Games Begin
###########################################################################################
$Progress = "Collecting Data"

Write-Log -Path $LogFilename -Message "Script Started" -Component $Progress  -Type Info
$SystemAccount = Import-CSV -Path SystemAccounts.csv
Write-Log -Path $LogFilename -Message "Account Lookup CSV Loaded" -Component $Progress  -Type Info

Write-Log -Path $LogFilename -Message "Starting the AD Query - Get-ADUser -Filter *  -Properties * | select SamAccountName,CN,Title,Department,Enabled,SID,UserPrincipalName,DisplayName,Description,useraccountcontrol,PasswordNeverExpires,@{Name='LastLogonDate';Expression={[DateTime]::FromFileTime($_.LastLogon)}},@{Name='PasswordLastSet';Expression={[DateTime]::FromFileTime($_.pwdLastSet)}} " -Component $Progress  -Type Info
$Data= (Get-ADUser -Filter *  -Properties * | select SamAccountName,CN,Title,Department,Enabled,SID,UserPrincipalName,DisplayName,Description,useraccountcontrol,PasswordNeverExpires,@{Name='LastLogonDate';Expression={[DateTime]::FromFileTime($_.LastLogon)}},@{Name='PasswordLastSet';Expression={[DateTime]::FromFileTime($_.pwdLastSet)}} )
Write-Log -Path $LogFilename -Message 'AD Query Completed' -Component $Progress  -Type Info
Write-Log -Path $LogFilename -Message 'Commencing the creation of Magic' -Component $Progress  -Type Info
Write-Log -Path $LogFilename -Message 'Creating Empty Array List' -Component $Progress  -Type Info
[System.Collections.ArrayList]$ArrayWithHeader = @()
$Progress = "Parsing Data"

##### For Each Record from AD the following should be performed #####

foreach ($order1 in $Data)
    {
 #Set the Defaults
    $AccCompliance =" "
    $AccType = "!!!! New Account !!!!"
#Pull the variabled from the array
    $Enabled = $order1.'Enabled'
#Test For known
    foreach ($order2 in $SystemAccount)
      {
        if( $order1.'SamAccountName' -eq $order2.'SamAccountName' ) 
          {

            $AccType = $order2.'Type'
         }                                                                  
      }
 #### End of System Account Test #####
        if($order1.'PasswordLastSet') 
          {
           $test = $order1.'PasswordLastSet'
           $testpattern = 'MM/dd/yyyy HH:mm:ss'
           $EndDate = [DateTime]::ParseExact($test, $testpattern, $null)
           $EndDate = NEW-TIMESPAN –Start $EndDate –End $StartDate
           $DaysFromPasswordLastSet = $EndDate.Days
          }   
          else
          {
          $DaysFromPasswordLastSet = "Password Never Set"
          }

        if($order1.'LastLogonDate') 
          {
           $test = $order1.'LastLogonDate'
           $testpattern = 'MM/dd/yyyy HH:mm:ss'
           $EndDate = [DateTime]::ParseExact($test, $testpattern, $null)
           $EndDate = NEW-TIMESPAN –Start $EndDate –End $StartDate
           $LastLogonDate = $EndDate.Days
          }   
          else
          {
          $LastLogonDate = "Never Logged on"
          }

#### End of Last Logon Test #####
          switch($order1.'userAccountControl')                    
          {
               512     
                   {
                       $AccCntrl = "Normal Account"
                       if( $LastLogonDate -le $MaxPasswordAge ) 
                         {
                           $AccCompliance = "Compliant Account" 
                           $CompliancePosture = "No Risk - Account login within policy"
                         }
                       else
                         {
                           $AccCompliance = "Non-Compliant Account" 
                           $CompliancePosture = "Risk - Account needs to have password which expires every $MaxPasswordAge days"
                         }
                       break
                   } 
               514
                   {
                       $AccCntrl = "Normal Account | Account Disabled"
                       $AccCompliance = "Compliant Account" 
                       $CompliancePosture = "No Risk - Disabled account"
                       break
                   }                
               544     
                   {
                       $AccCntrl = "Normal Account | Password Not Required"
                       $AccCompliance = "Non-Compliant Account" 
                       $CompliancePosture = "Risk - Password Not Required"
                       break
                   }                
               546     
                   {
                       $AccCntrl = "Normal Account | Disabled account"
                       $AccCompliance = "Compliant Account" 
                       $CompliancePosture = "No Risk - Disabled account"
                       break
                   }           
               66048
                   {
                       $AccCntrl = "Normal Account | Password Doesnt Expire"
                       $AccCompliance = "Non-Compliant Account" 
                       $CompliancePosture = "Risk - Password Not Expire"
                       break
                   }          
               66050
                   {
                       $AccCntrl = "Normal Account | Password Doesnt Expire | Account Disabled"
                       $AccCompliance = "Compliant Account" 
                       $CompliancePosture = "Risk - Password Doesnt Expire, Disabled account"
                       break
                   }          
               66080
                   {
                       $AccCntrl = "Normal Account | Password Doesnt Expire | Password Not Required"
                       $AccCompliance = "Non-Compliant Account" 
                       $CompliancePosture = "Risk - Password in not Required"
                       break
                   }        
               66082
                   {
                       $AccCntrl = "Normal Account | Password Doesnt Expire | Password Not Required | Account Disabled"
                       $AccCompliance = "Compliant Account" 
                       $CompliancePosture = "Risk - Password Doesnt Expire, Password Not Required, Disabled account"
                       break
                   }          
               8388608
                   {
                       $AccCntrl = "Password Expired"
                       $AccCompliance = "Compliant Account" 
                       $CompliancePosture = "No Risk - Password Expired"
                       break
                   }
               1049088
                   {
                       $AccCntrl = "Normal Account"
                       if( $LastLogonDate -le $MaxPasswordAge ) 
                         {
                           $AccCompliance = "Compliant Account" 
                           $CompliancePosture = "No Risk - Account login within policy"
                         }
                       else
                         {
                           $AccCompliance = "Non-Compliant Account" 
                           $CompliancePosture = "Risk - Account needs to have password which expires every $MaxPasswordAge days"
                         }
                         break
                   }          
               1049090
                   {
                       $AccCntrl = "Normal Account | Disabled account | Not Delegated"
                       $AccCompliance = "Compliant Account" 
                       $CompliancePosture = "No Risk - Disabled account"
                       break
                   }           
               1114624
                   {
                       $AccCntrl = "Normal Account | Do Not Expire | Not Delegated "
                       $AccCompliance = "Compliant Account" 
                       $CompliancePosture = "Risk - Password does not Expire"
                       break
                   }   
               2080 
                   {
                       $AccCntrl = "InterDomain Trust Account - Password Not Required"
                       $AccCompliance = "Compliant Account" 
                       $CompliancePosture = "Special Account"
                       break
                   }           
              default
                   {
                      $AccCntrl = "Unknown User Account Control"
                       $AccCompliance = "Unknown User Account Control" 
                       $CompliancePosture = "Unknown User Account Control"
                    }
          }   


$val = [pscustomobject]@{
'SAM Account Name' = $order1.SamAccountName;
'CN' = $order1.CN;
'Display Name' = $order1.DisplayName;
'Description' = $order1.Description;
'SID' = $order1.SID;
'Title' = $order1.Title;
'Department' = $order1.Department;
'User Principal Name' = $order1.UserPrincipalName;
'userAccountControl' = $order1.userAccountControl;
'User Account Control' = $AccCntrl;
'Account Type' = $AccType;
'Last Logon Date' = $order1.'LastLogonDate';
'Account Enabled' = $Enabled;
'Password Set Date' = $order1.'PasswordLastSet';
'Days Since Password Set' = $DaysFromPasswordLastSet;
'Last Login Date' = $order1.'LastLogonDate';
'Days Since Last Login' = $LastLogonDate;
'Account Compliance' = $AccCompliance;
'Compliance Posture' = $CompliancePosture}


$ArrayWithHeader.add($val) | Out-Null

$val=$null
   }

$Progress = "Generating Output"

Write-Log -Path $LogFilename -Message 'All Data validated and added to Aray' -Component $Progress  -Type Info

$ArrayWithHeader | export-Csv -NoTypeInformation $Filename
Write-Log -Path $LogFilename -Message "Exporting data to : $Filename" -Component $Progress  -Type Info
Write-Log -Path $LogFilename -Message 'Preparing to fix the CSV File' -Component $Progress  -Type Info
$sep = "SEP=,`r`n" 
$sep + (Get-Content -Path $Filename -Raw) | Set-Content -Path $Filename
Write-Log -Path $LogFilename -Message 'Added the SEP setting to the top of the file' -Component $Progress  -Type Info



if ($emailAlerts -eq $True )
    {
    $Progress = "Mailing"
        Write-Log -Path $LogFilename -Message 'Mailing report to ' -Component $Progress  -Type Info
        Send-MailMessage @mailParams
    }
    else
    {
        Write-Log -Path $LogFilename -Message 'Mailing Was not requested' -Component $Progress  -Type warning
    }

$Progress = "Wrapup and Housekeeping"
Write-Log -Path $LogFilename -Message 'All Done' -Component $Progress  -Type Info
Write-Log -Path $LogFilename -Message '==================================================================================================================' -Component $Progress  -Type Info
