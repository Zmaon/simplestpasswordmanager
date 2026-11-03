# The Simplest Password Manager

This is the source code of https://www.tspm.ch, a very simple "password manager" that generates passwords from an easy to remember master passphrase and the name of the website.

The idea is to keep the project as simple as possible, so no server side scripting, no npm, no js compilation, no babel, no webpack, and no dependencies at all: the page is `index.html`, `password_manager.js` and `css/main.css`, nothing else.

## Installing

Clone the repo and double-click on `index.html` to open it with your favorite browser, that's it!

When hosted, `.htaccess` adds HSTS and a Content Security Policy that only allows the site's own files and blocks requests from the page to other sites (fetch, XHR, images). It's a safety net, not a guarantee: it can't stop a script from navigating away with data, and it doesn't help if the server itself is compromised. It needs Apache's `mod_headers`; check the headers with `curl -I https://www.tspm.ch` after deploying.

## How passwords are generated

The recipe is public on purpose, so that anyone can regenerate their passwords without this website. All strings are encoded in UTF-8.

### v2 (current)

1. `seed = PBKDF2-HMAC-SHA256(password = NFC(passphrase), salt = "tspm-v2:" + lowercase(trim(NFC(site))), iterations = 600000, length = 32 bytes)`
2. `bytes = HKDF-SHA256(key = seed, salt = empty, info = "tspm-v2-chars", length = 128 bytes)`, read as 32 big-endian uint32 values `u0, u1, …`, consumed in order. `draw(n)` returns the next one modulo `n`.
3. With the classes `abcdefghijklmnopqrstuvwxyz`, `ABCDEFGHIJKLMNOPQRSTUVWXYZ`, `0123456789` and `!#$%&*+-=?@_`: pick the first 4 characters one from each class, in that order, then 12 more from the 4 classes concatenated (74 characters), each time with `set[draw(set.length)]`.
4. Shuffle the 16 characters with Fisher-Yates: for `i` from 15 down to 1, swap `chars[i]` and `chars[draw(i + 1)]`.

### v1 (deprecated)

`digest = SHA-256(passphrase)`, then for `i = 0, 2, …, 30`: `chars[(digest[i] XOR digest[i + 1]) mod 65]` with `chars = 0-9A-Za-z!@#`. A single fast hash makes it easy to brute-force the passphrase from one leaked password, which is why v2 exists. v1 is only kept so that users can log in with their old passwords and change them.

### Test vectors

| Passphrase | Website | v1 | v2 |
| --- | --- | --- | --- |
| `correct horse battery staple` | `github` | `!HsrZ2w9CmasrQtG` | `&3f=rfT_C@IBC*rh` |
| `My great password for Github` | `  GitHub ` | `iWpu0mC3eO!#C49W` | `&Vluey%6?Qh3k&Os` |
| `p` | `x` | `Ni3J7sEx@V9xGELM` | `FJ%nsqY3hn$3tXr&` |

## Credits

The idea of generating passwords from a sentence that you can easily remember is not new. I read an article a few years ago defending this approach, and I found it really interesting. It came with a command line software. Unfortunately, I don't    remember the name of the author and can't find the article anymore. 
