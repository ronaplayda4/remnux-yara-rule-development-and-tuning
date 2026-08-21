rule My_First_YARA_Rule
{
    meta:
        description = "Detects simulated PowerShell download activity for REMnux YARA lab"
        author = "Rona Playda"
        purpose = "Educational SOC portfolio lab"

    strings:
        $a = "powershell" nocase
        $b = "Invoke-WebRequest" nocase
        $c = "cmd.exe" nocase

    condition:
        $b and ($a or $c)
}
