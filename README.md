# go-turnstile




### usage
```

t := NewTurnstileVerifier("my-secret")


verified, err := t.Verify(token)
if err != nil || !verified.Success {
	log.Printf("failed to verify")
}

```
