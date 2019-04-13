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
				const byteArray = new Uint8Array(digestValue);
				this.$output.val(this._smallify(byteArray));
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
			var copyOk = false;
			if(!this.$output.val()){
				return;
			}

			if(document.queryCommandSupported('copy')){
				var initialType = this.$output.attr("type");
				this.$output.attr("type", "text").select().select(); // 2 select() because Safari doesn't always understand the first time.

				try {
					document.execCommand('copy');
					copyOk = true;
					this.$copyOutput.width(this.$copyOutput.width()).html('<i class="fa fa-check"></i>');
					clearTimeout(this.copyTimeout);
					this.copyTimeout = setTimeout(() => {
						this.$copyOutput.html('Copy to clipboard');
					}, 1500);
				} catch (err) {
				}

				this.$output.attr("type", initialType).blur();
			}

			if(!copyOk){
				window.prompt("Copy to clipboard is not supported on your browser, please copy manually:", this.$output.val());
			}
		}
	}

	jQuery.fn.PasswordManager = function (settings) {
		return new PasswordManager($(this).eq(0), settings);
	};
})();