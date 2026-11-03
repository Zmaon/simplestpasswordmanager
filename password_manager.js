(() => {
	'use strict';

	const STORAGE_KEY = 'tspm.version';
	const THEME_STORAGE_KEY = 'tspm.theme';

	const V1_CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#';

	const V2_ITERATIONS = 600000;
	const V2_LENGTH = 16;
	// The first V2_CLASSES.length characters are drawn one from each class, so every password
	// passes the usual "lowercase, uppercase, digit and symbol" rules.
	const V2_CLASSES = [
		'abcdefghijklmnopqrstuvwxyz',
		'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
		'0123456789',
		'!#$%&*+-=?@_'
	];

	// Icons from Font Awesome Free, CC BY 4.0.
	const SUN_ICON = '<svg class="icon" viewBox="0 0 512 512" aria-hidden="true"><path transform="matrix(1 0 0 -1 0 448)" d="M256 288c52.9004 0 96 -43.0996 96 -96s-43.0996 -96 -96 -96s-96 43.0996 -96 96s43.0996 96 96 96zM502.4 207.5c12.7998 -6.40039 12.7998 -24.5996 -0.200195 -31.0996l-94.7002 -47.3008l33.5 -100.399c4.59961 -13.5 -8.2998 -26.4004 -21.9004 -21.9004 l-100.399 33.5l-47.2998 -94.7002c-6.40039 -12.7998 -24.6006 -12.7998 -31 0l-47.3008 94.7002l-100.399 -33.5c-13.5 -4.59961 -26.4004 8.2998 -21.9004 21.9004l33.5 100.5l-94.7002 47.2998c-12.7998 6.40039 -12.7998 24.5996 0 31l94.7002 47.4004l-33.5 100.399 c-4.59961 13.5 8.2998 26.4004 21.9004 21.9004l100.5 -33.5l47.2998 94.7002c6.40039 12.7998 24.5996 12.7998 31 0l47.4004 -94.8008l100.399 33.5c13.5 4.60059 26.4004 -8.2998 21.9004 -21.8994l-33.5 -100.4zM346.5 101.5c49.9004 49.9004 49.9004 131.1 0 181 s-131.1 49.9004 -181 0s-49.9004 -131.1 0 -181s131.1 -49.9004 181 0z"/></svg>';
	const MOON_ICON = '<svg class="icon" viewBox="0 0 512 512" aria-hidden="true"><path transform="matrix(1 0 0 -1 0 448)" d="M283.211 -64c-141.489 0 -256 114.691 -256 256c0 141.489 114.691 256 256 256c13.0176 -0.00195312 33.9727 -1.91895 46.7754 -4.28027c11.0059 -2.0332 13.4414 -16.7178 3.75586 -22.2295c-62.8359 -35.7588 -101.498 -102.172 -101.498 -174.395 c0 -125.378 114.059 -220.607 238.262 -196.954c10.9229 2.08008 18.6299 -10.6416 11.5625 -19.3496c-47.7783 -58.8672 -119.896 -94.792 -198.857 -94.792z"/></svg>';
	const CHECK_ICON ='<svg class="icon" viewBox="0 0 512 512" aria-hidden="true"><path transform="matrix(1 0 0 -1 0 448)" d="M173.898 8.5957l-166.4 166.4c-9.99707 9.99707 -9.99707 26.2061 0 36.2041l36.2031 36.2041c9.99707 9.99805 26.207 9.99805 36.2041 0l112.095 -112.095l240.095 240.095c9.99707 9.99707 26.207 9.99707 36.2041 0l36.2031 -36.2041 c9.99707 -9.99707 9.99707 -26.2061 0 -36.2041l-294.4 -294.401c-9.99805 -9.99707 -26.207 -9.99707 -36.2031 0.000976562z"/></svg>';

	const encoder = new TextEncoder();

	/**
	 * v1 (deprecated): a single unsalted SHA-256 of the passphrase.
	 * Kept only so that existing passwords can be recovered, then changed.
	 */
	async function deriveV1(passphrase){
		const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(passphrase)));
		let password = '';
		for (let i = 0; i < digest.length; i += 2) {
			password += V1_CHARS[(digest[i] ^ digest[i + 1]) % V1_CHARS.length];
		}
		return password;
	}

	function normalizeSite(site){
		return site.normalize('NFC').trim().toLowerCase();
	}

	/**
	 * v2: PBKDF2-HMAC-SHA256 of the master passphrase, salted with the site, so that every guess
	 * costs an attacker 600k hashes. The 32-byte result is expanded with HKDF into the bytes used
	 * to pick and shuffle the characters.
	 */
	async function deriveV2(passphrase, site){
		const masterKey = await crypto.subtle.importKey('raw', encoder.encode(passphrase.normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
		const seed = await crypto.subtle.deriveBits({
			name: 'PBKDF2',
			hash: 'SHA-256',
			salt: encoder.encode('tspm-v2:' + normalizeSite(site)),
			iterations: V2_ITERATIONS
		}, masterKey, 256);

		const seedKey = await crypto.subtle.importKey('raw', seed, 'HKDF', false, ['deriveBits']);
		const bytes = await crypto.subtle.deriveBits({
			name: 'HKDF',
			hash: 'SHA-256',
			salt: new Uint8Array(0),
			info: encoder.encode('tspm-v2-chars')
		}, seedKey, V2_LENGTH * 2 * 32);

		// Each draw takes the next big-endian uint32. Its modulo bias for n <= 74 is below 2^-25.
		const view = new DataView(bytes);
		let draws = 0;
		const draw = n => view.getUint32(4 * draws++) % n;

		const allChars = V2_CLASSES.join('');
		const chars = [];
		for (let i = 0; i < V2_LENGTH; i++) {
			const set = i < V2_CLASSES.length ? V2_CLASSES[i] : allChars;
			chars.push(set[draw(set.length)]);
		}
		// Fisher-Yates, so the guaranteed characters don't always sit at the start.
		for (let i = chars.length - 1; i > 0; i--) {
			const j = draw(i + 1);
			[chars[i], chars[j]] = [chars[j], chars[i]];
		}
		return chars.join('');
	}

	function loadVersion(){
		try {
			const version = localStorage.getItem(STORAGE_KEY);
			if(version === 'v1' || version === 'v2'){
				return version;
			}
		} catch (err) {
			// Storage can be unavailable (private mode, blocked site data): fall back to the default.
		}
		return 'v2';
	}

	function saveVersion(version){
		try {
			localStorage.setItem(STORAGE_KEY, version);
		} catch (err) {
			// Not remembering the choice is fine.
		}
	}

	const darkSystem = window.matchMedia('(prefers-color-scheme: dark)');

	function currentTheme(){
		return document.documentElement.dataset.theme || (darkSystem.matches ? 'dark' : 'light');
	}

	/**
	 * Without a saved choice the page follows the system theme (see the CSS).
	 */
	function loadTheme(){
		try {
			const theme = localStorage.getItem(THEME_STORAGE_KEY);
			if(theme === 'light' || theme === 'dark'){
				document.documentElement.dataset.theme = theme;
			}
		} catch (err) {
			// Storage can be unavailable: follow the system theme.
		}
	}

	function saveTheme(theme){
		// Switch every color at once instead of letting the buttons' hover transitions lag behind.
		const root = document.documentElement;
		root.classList.add('theme-switching');
		root.dataset.theme = theme;
		requestAnimationFrame(() => requestAnimationFrame(() => root.classList.remove('theme-switching')));
		try {
			localStorage.setItem(THEME_STORAGE_KEY, theme);
		} catch (err) {
			// The choice still applies to this page.
		}
	}

	function initThemeToggle(button){
		// The button shows the theme it switches to.
		const update = () => {
			const next = currentTheme() === 'dark' ? 'light' : 'dark';
			button.innerHTML = next === 'dark' ? MOON_ICON : SUN_ICON;
			button.title = `Switch to ${next} theme`;
			button.setAttribute('aria-label', button.title);
		};
		button.addEventListener('click', () => {
			saveTheme(currentTheme() === 'dark' ? 'light' : 'dark');
			update();
		});
		darkSystem.addEventListener('change', update);
		update();
	}

	// Runs from <head>, before the first paint, so a saved theme doesn't flash the other one.
	loadTheme();

	class PasswordManager {
		constructor(root) {
			this.root = root;
			this.passphrase = root.querySelector('#passphrase');
			this.passphraseLabel = root.querySelector('label[for="passphrase"]');
			this.site = root.querySelector('#site');
			this.siteGroup = root.querySelector('.site-group');
			this.output = root.querySelector('#password-output');
			this.copyOutput = root.querySelector('#button-copy-output');
			this.versionButtons = root.querySelectorAll('[data-version]');
			this.v1Warning = root.querySelector('.v1-warning');
			this.copyTimeout = null;
			// Increments on every generation, so a slow derivation can't overwrite a newer result.
			this.generation = 0;

			this._init();
		}

		_init() {
			let timeout = null;
			const scheduleGenerate = () => {
				clearTimeout(timeout);
				timeout = setTimeout(() => this._generate(), 350);
			};
			this.passphrase.addEventListener('input', scheduleGenerate);
			this.site.addEventListener('input', scheduleGenerate);

			this.root.querySelector('form').addEventListener('submit', event => event.preventDefault());

			this.root.querySelector('#button-show-passphrase').addEventListener('click', event => {
				this._toggleShowText(this.passphrase, event.currentTarget);
			});

			this.root.querySelector('#button-show-output').addEventListener('click', event => {
				this._toggleShowText(this.output, event.currentTarget);
			});

			this.copyOutput.addEventListener('click', () => this._copyToClipboard());

			this.versionButtons.forEach(button => {
				button.addEventListener('click', () => {
					saveVersion(button.dataset.version);
					this._setVersion(button.dataset.version);
				});
			});

			this._setVersion(loadVersion());
			this.passphrase.focus();
		}

		_setVersion(version){
			this.version = version;
			this.versionButtons.forEach(button => {
				button.setAttribute('aria-pressed', String(button.dataset.version === version));
			});
			this.siteGroup.hidden = version === 'v1';
			this.v1Warning.hidden = version !== 'v1';
			this.passphraseLabel.textContent = version === 'v1' ? 'Passphrase' : 'Master passphrase';
			this._generate();
		}

		_toggleShowText(input, button){
			if(input.type === 'password'){
				input.type = 'text';
				button.textContent = 'Hide';
			} else {
				input.type = 'password';
				button.textContent = 'Show';
			}
		}

		_generate(){
			const generation = ++this.generation;
			const passphrase = this.passphrase.value;
			const site = this.site.value;

			this.output.value = '';
			if(!passphrase || (this.version === 'v2' && !normalizeSite(site))){
				this.output.placeholder = 'Password';
				return;
			}

			this.output.placeholder = 'Generating…';
			const derivation = this.version === 'v1' ? deriveV1(passphrase) : deriveV2(passphrase, site);
			derivation.then(password => {
				if(generation === this.generation){
					this.output.value = password;
					this.output.placeholder = 'Password';
				}
			}).catch(err => console.error(err));
		}

		_copyToClipboard(){
			const text = this.output.value;
			if(!text){
				return;
			}

			// Clipboard API: works on all modern browsers (incl. Safari iOS 13.4+), requires HTTPS.
			// Must be called synchronously from the click handler for Safari to accept it.
			if(navigator.clipboard && window.isSecureContext){
				navigator.clipboard.writeText(text)
					.then(() => this._showCopySuccess())
					.catch(err => {
						console.error(err);
						this._legacyCopyToClipboard(text);
					});
				return;
			}

			this._legacyCopyToClipboard(text);
		}

		/**
		 * Fallback for older browsers, using a temporary textarea and execCommand('copy').
		 */
		_legacyCopyToClipboard(text){
			const textarea = document.createElement('textarea');
			textarea.value = text;
			textarea.setAttribute('readonly', '');
			textarea.style.position = 'fixed';
			textarea.style.top = '0';
			textarea.style.left = '0';
			textarea.style.opacity = '0';
			textarea.style.fontSize = '16px'; // Prevents zoom on iOS.
			document.body.appendChild(textarea);

			textarea.select();
			textarea.setSelectionRange(0, text.length); // Needed on iOS.

			let copyOk = false;
			try {
				copyOk = document.execCommand('copy');
			} catch (err) {
				console.error(err);
			}

			document.body.removeChild(textarea);
			this.copyOutput.blur();

			if(copyOk){
				this._showCopySuccess();
			} else {
				window.prompt('Copy to clipboard is not supported on your browser, please copy manually:', text);
			}
		}

		_showCopySuccess(){
			this.copyOutput.innerHTML = CHECK_ICON + 'Copied';
			clearTimeout(this.copyTimeout);
			this.copyTimeout = setTimeout(() => {
				this.copyOutput.textContent = 'Copy';
			}, 1500);
		}
	}

	function initContactLink(link){
		link.addEventListener('mousedown', () => {
			link.href = 'mailto:' + atob(atob('ZEdobGMybHRjR3hsWTI5dWRHRmpkR1Z0WVdsc1FIUm9aWE5wYlhCc1pYQmhjM04zYjNKa2JXRnVZV2RsY2k1amIyMD0='));
			setTimeout(() => {
				link.href = '#';
			}, 250);
		});
	}

	document.addEventListener('DOMContentLoaded', () => {
		const container = document.querySelector('.password-container');
		if(container){
			new PasswordManager(container);
		}
		document.querySelectorAll('.contact').forEach(initContactLink);
		document.querySelectorAll('.theme-toggle').forEach(initThemeToggle);
	});
})();
