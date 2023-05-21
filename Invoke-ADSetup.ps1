function Write-OK { 
	param( $text ) 
		Write-Host "[*]" $text "`t[*]" -ForegroundColor 'Green' 
}

function Invoke-ADSetup {
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$domainName
	)

	Write-OK "Include Management Tools"
	Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

	$netBIOSName = $domainName.split('.')[0]

	Write-OK "Promote to Domain Controller"
	Install-ADDSForest -DomainName $domainName -DomainNetBiosName $netBIOSName -InstallDNS:$true -Force

	Write-OK "=================================="
	Write-OK "Restart the server before continue"
	Write-OK "=================================="
}
