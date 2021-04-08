$testStr = "http://someuser:somepassword@thingydomain.com"
$regex = "^(?<protocol>.+?\/\/)(?<username>.+?):(?<password>.+?)@(?<address>.+)$"
$result = [regex]::Matches($testStr, $regex)
$stringThing = $($result[0].Groups['protocol'].Value) + $($result[0].Groups['username'].Value) + ":*********@" + $($result[0].Groups['address'].Value)
$stringThing
