(() => {
	'use strict';

	const STORAGE_KEY = 'tspm.version';

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
				const active = button.dataset.version === version;
				button.classList.toggle('btn-primary', active);
				button.classList.toggle('btn-outline-primary', !active);
				button.setAttribute('aria-pressed', String(active));
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
			this.copyOutput.style.width = this.copyOutput.offsetWidth + 'px';
			this.copyOutput.innerHTML = '<i class="fa fa-check"></i>';
			clearTimeout(this.copyTimeout);
			this.copyTimeout = setTimeout(() => {
				this.copyOutput.textContent = 'Copy to clipboard';
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
	});
})();
