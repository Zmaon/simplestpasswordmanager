(() => {
	'use strict';
	class PasswordManager {
		constructor(dom, settings) {
			this.$dom = $(dom);
			this.settings = settings;
			this.$passphrase = this.$dom.find('input#passphrase');
			this.$output = this.$dom.find('input#password-output');
			this.$showPassphrase = this.$dom.find('button#button-show-passphrase');
			this.$showOutput = this.$dom.find('button#button-show-output');
			this.$copyOutput = this.$dom.find('button#button-copy-output');
			this.copyTimeout = null;

			this._init();
		}

		_init() {
			let timeout = null;
			this.$dom.find('input#passphrase').on('keyup blur', () => {
				clearTimeout(timeout);
				timeout = setTimeout(() => {
					this._generate(this.$passphrase.val());
				}, 350);
			}).focus();

			this.$showPassphrase.on('click', event => {
				this._toggleShowText(this.$passphrase, $(event.currentTarget));
				return false;
			});

			this.$showOutput.on('click', event => {
				this._toggleShowText(this.$output, $(event.currentTarget));
				return false;
			});

			this.$copyOutput.on('click', () => {
				this._copyToClipboard();
				return false;
			});
		}

		_toggleShowText($input, $button){
			if($input.attr('type') === 'password'){
				$input.attr('type', 'text');
				$button.text('Hide');
			} else {
				$input.attr('type', 'password');
				$button.text('Show');
			}
		}

		_generate(passphraseTxt){
			if(!passphraseTxt){
				this.$output.val('');
				return;
			}

			const encoder = new TextEncoder();
			const data = encoder.encode(passphraseTxt);

			const digest = crypto.subtle.digest('SHA-256', data);
			digest.then(digestValue => {
				const intArray = new Uint8Array(digestValue);
				this.$output.val(this._smallify(intArray));
			});
		}

		_smallify(intArray){
			const chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#";
			let password = [];
			for (let i = 0; i < intArray.length; i+=2) {
				password[i] = chars[(intArray[i] ^ intArray[i + 1]) % chars.length];
			}
			return password.join('');
		}

		_copyToClipboard(){
			const text = this.$output.val();
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
			this.$copyOutput.blur();

			if(copyOk){
				this._showCopySuccess();
			} else {
				window.prompt('Copy to clipboard is not supported on your browser, please copy manually:', text);
			}
		}

		_showCopySuccess(){
			this.$copyOutput.width(this.$copyOutput.width()).html('<i class="fa fa-check"></i>');
			clearTimeout(this.copyTimeout);
			this.copyTimeout = setTimeout(() => {
				this.$copyOutput.html('Copy to clipboard');
			}, 1500);
		}
	}

	jQuery.fn.PasswordManager = function (settings) {
		return new PasswordManager($(this).eq(0), settings);
	};
})();