# What?
Food is highly subjective. Instead of using online recipe generators or LLMs, why not store recipes (tailored to your taste) as YARA rules, which can be queried based on your pantry? 

# Usage

```bash
yara -m meals/easy.yara pantry
```

# Example recipe
```yara
rule Burrito {
    meta:
        author = "Sid"
        description = "[Medium effort]"
    strings:
        $base1 = "tortilla" nocase
        $base2 = "short grain rice" nocase
        $base3 = "black beans" nocase
        $base4 = "avocado" nocase

        $meat1 = "chicken" nocase
        $meat2 = "beef" nocase
        $meat3 = "pork" nocase

        $basic = "salt" nocase
        $basic2 = "pepper" nocase

        $seasoning1 = "cumin" nocase
        $seasoning2 = "chili powder" nocase
        $seasoning3 = "paprika" nocase
        $seasoning4 = "garlic powder" nocase
        $seasoning5 = "onion powder" nocase
        $seasoning6 = "cayenne pepper" nocase
        $seasoning7 = "oregano" nocase

        $cheese1 = "cheddar cheese" nocase
        $cheese2 = "monterey jack" nocase

        $optional2 = "lettuce" nocase
        $optional3 = "tomatoes" nocase
        $optional4 = "onions" nocase
        $optional5 = "jalapenos" nocase
        $optional6 = "cilantro" nocase
        $optional7 = "lime" nocase
        $optional8 = "sour cream" nocase

    condition:
        all of ($base*) 
        and all of ($basic*)
        and all of ($seasoning*)
        and any of ($cheese*)
        and any of ($meat*) 
        and any of ($optional*)
}
```

So technically, the "optional" ingredients aren't optional because of the 'any of' keyword. You can change the conditions and comment out the optional ingredients.