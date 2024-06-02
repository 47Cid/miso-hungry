# What?
Food is highly subjective. Instead of using online recipe generators or LLMs, why not store recipes (tailored to your taste) as YARA rules, which can be queried based on your pantry? 

# Usage

```bash
yara -m meals/easy.yara pantry
```

So technically, the "optional" ingredients aren't optional because of the 'any of' keyword. You can change the conditions and comment out the optional ingredients.