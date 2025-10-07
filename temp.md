### Easiest CSRF Protection

The `<CsrfInput /` component is designed for maximum ease of use. Simply place it in your form. It will automatically fetch the required token.

**1. Define a Server Action to get the token:**

```ts
// app/auth/actions.ts
"use server";
import { auth } from "@/lib/auth";

export async function getCsrfTokenAction() {
  return auth.getCsrfToken();
}
```

**2. Use `CsrfInput` in your form:**

```tsx
// your-form-component.tsx
"use client";
import { CsrfInput } from "@waelhabbaldev/next-jwt-auth/client";
import { getCsrfTokenAction } from "@/app/auth/actions";

export function MyForm() {
  return (
    <form action={...}
      <CsrfInput getTokenAction={getCsrfTokenAction} /
      {/* ... rest of your form */}
    </form
  );
}
```
