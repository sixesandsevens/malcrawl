rule SuspiciousEval {
    meta:
        description = "Detect usage of eval in JavaScript"
    strings:
        $eval = /eval\(/i
    condition:
        $eval
}
