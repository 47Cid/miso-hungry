rule Grilled_Cheese {
    meta:
        author = "Sid"
        description = "[Medium effort]"
    strings:
        $basic1 = "butter" nocase

        $bread1 = "bread" nocase
        $bread2 = "sourdough bread" nocase
        
        $cheese1 = "gruyere" nocase
        $cheese2 = "mozzarella" nocase
        $cheese3 = "cheddar" nocase

        //$optional1 = "bacon" nocase
        //$optional2 = "mayo" nocase

    condition:
        all of ($basic*) 
        and any of ($bread*) 
        and any of ($cheese*)
}
