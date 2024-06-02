rule Okonomiyaki
{
    meta:
        author = "Sid"
        description = "Sweet and savoury japanese cabbage pancake [Medium effort]"
        date = "2024-05-31"

    strings:
        $base1 = "cabbage" nocase
        $base2 = "eggs" nocase
        $base3 = "flour" nocase

        $sauce1 = "ketchup" nocase
        $sauce2 = "soy sauce" nocase
        $sauce3 = "worcestershire sauce" nocase
        
        $sugar = "sugar" nocase
        $honey = "honey" nocase

        $basic1 = "salt" nocase
        $basic2 = "pepper" nocase

        $fat1 = "butter" nocase
        $fat2 = "olive oil" nocase
        $fat3 = "vegetable oil" nocase
        $fat4 = "sesame oil" nocase

         // Mayonnaise or Kewpie Mayonnaise
        $mayo1 = "mayo" nocase
        $mayo2 = "japanese mayo" nocase
        $mayo3 = "kewpie mayo" nocase
        $mayo4 = "mayonnaise" nocase
        $mayo5 = "kewpie mayonnaise" nocase


        $optional1 = "green onions" nocase
        $optional2 = "spring onions" nocase
        $optional3 = "sesame seeds" nocase
        $optional4 = "pickled ginger" nocase
        $optional5 = "bonito flakes" nocase
        $optional6 = "nori" nocase
        $optional7 = "kombu" nocase
        $optional8 = "dried shiitake mushrooms" nocase

    condition:
        all of ($base*) 
        and all of ($sauce*) 
        and  $sugar or $honey 
        and all of ($basic*) 
        and any of ($fat*) 
        and any of ($mayo*)
        and any of ($optional*) 
}

rule Carbonara {
    meta:
        author = "Sid"
        description = "Peas make a big difference [Medium effort]"
    strings:
        $base1 = "spaghetti" nocase
        $base2 = "eggs" nocase
        $base3 = "garlic" nocase
 
        $basic1 = "salt" nocase
        $basic2 = "pepper" nocase
        $basic3 = "olive oil" nocase

        $cheese1 = "parmesan" nocase
        $cheese2 = "parmigiano reggiano" nocase
        $cheese3 = "pecorino romano" nocase

        $optional1 = "guanciale" nocase
        $optional2 = "pancetta" nocase
        $optional3 = "bacon" nocase
        $optional4 = "peas" nocase
    condition:
        all of ($base*) 
        and all of ($basic*) 
        and any of ($cheese*) 
        and any of ($optional*)
}

rule Goncchi {
    meta:
        author = "Sid"
        description = "Pan-seared gnocchi with brown butter sauce [Medium effort]"
    strings:
        $base1 = "gnocchi" nocase
        $base2 = "butter" nocase
        $base3 = "garlic" nocase

        $basic1 = "salt" nocase
        $basic2 = "pepper" nocase

        $seasoning1 = "italian seasoning" nocase
        $seasoning2 = "oregano" nocase

        // $optional1 = "bacon" nocase
        // $optional2 = "thyme" nocase
        // $optional3 = "rosemary" nocase
        // $optional4 = "parmesan" nocase
    condition:
        all of ($base*) 
        and all of ($basic*) 
        and any of ($seasoning*) 
}

rule Basic_Ramen {
    meta:
        author = "Sid"
        description = "Make sure to marinate the chicken/beef with baking soda [Medium effort]"
    strings:
        $noodles = "noodles" nocase
        $noodels2 = "ramen noodles" nocase

        $base1 = "ramen seasoning" nocase
        $base2 = "eggs" nocase

        $chicken = "chicken" nocase
        $beef = "beef" nocase

        $optional1 = "green onions" nocase
        $optional2 = "spring onions" nocase
        $optional3 = "sesame seeds" nocase
        $optional4 = "pickled ginger" nocase
        $optional5 = "bonito flakes" nocase
        $optional6 = "nori" nocase

    condition:
        ($noodles or $noodels2) 
        and ($base1 and $base2)
        and ($chicken or $beef)
        and any of ($optional*)
}
