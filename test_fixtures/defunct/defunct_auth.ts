// Deliberately defunct: missing imports, wrong types, bad logic
export class AuthService {
  private users: Map<string, any> = new Map();

  createUser(email: string, password: string) {
    if (!email.includes("@")) throw new Error("BAD_EMAIL");
    const hash = sha256(password); // sha256 not defined
    this.users.set(email, { email, hash });
    return { ok: true };
  }

  login(email: string, password: string) {
    const u = this.users.get(email);
    if (!u) throw new Error("NO_USER");
    const hash = sha256(password); // sha256 not defined
    if (hash != u.hash) throw new Error("BAD_PASS");
    return signJwt({ sub: email }); // signJwt not defined
  }
}
