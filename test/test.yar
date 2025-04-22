rule find_yes {
    strings:
        $yes01 = "yes" fullword nocase ascii wide 
        $yes02 = "yes" base64 base64wide
        $yes03 = "Yes" base64 base64wide
        $yes04 = "YES" base64 base64wide
    condition:
        any of them
}
