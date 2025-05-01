rule find_yes {
    strings:
        $yes01 = "yes" fullword nocase ascii wide 
    condition:
        any of them
}
