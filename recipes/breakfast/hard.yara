rule Cilbir {
    meta:
        author = "Sid"
        description = "Turkish eggs [Medium effort]"
    strings:
        $base1 = "eggs" nocase
        $base2 = "greek yogurt" nocase
        $base3 = "dill" nocase
        $base4 = "garlic" nocase
        $base5 = "smoked paprika" nocase
        $base6 = "olive oil" nocase
        $base7 = "butter" nocase
        $base8 = "chili flakes" nocase

        //$optional1 = "mint" nocase
        //$optional2 = "cumin" nocase


    condition:
        all of ($base*)
}
