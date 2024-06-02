rule Orange_Chicken {
    meta:
        author = "Sid"
        description = "One pan orange fried chicken without deep-frying [Medium effort]"
    strings:
        $base1 = "chicken" nocase
        $base2 = "corn starch" nocase

        $sauce1 = "orange juice" nocase
        $sauce2 = "soy sauce" nocase
        $sauce3 = "rice vinegar" nocase
        $sauce5 = "garlic" nocase
        $sauce6 = "ginger" nocase

        $sweetener1 = "sugar" nocase
        $sweetener2 = "honey" nocase
        $sweetner3 = "brown sugar" nocase

        $seasoning1 = "salt" nocase
        $seasoning2 = "pepper" nocase

        $optional1 = "green onions" nocase
        $optional2 = "spring onions" nocase
        $optional3 = "sesame seeds" nocase
        $optional4 = "red pepper flakes" nocase
        $optional6 = "sesame oil" nocase
        $optional7 = "long grain rice" nocase

    condition:
        all of ($sauce*) 
        and all of ($sweetener*) 
        and all of ($seasoning*)
}
