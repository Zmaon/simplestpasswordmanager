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
			if(!this.$output.val()){
				return;
			}

			if(!document.queryCommandSupported('copy')){
				return false; // Todo: display a nice error to user.
			}

			let ua = window.navigator.userAgent;
			let iOS = !!ua.match(/iPad/i) || !!ua.match(/iPhone/i) || !!ua.match(/iPod/i);
			let webkit = !!ua.match(/WebKit/i);
			let iOSSafari = iOS && webkit && !ua.match(/CriOS/i);

			if(iOSSafari){
				this._iOSCopyToClipboard();
			} else {
				this._stdCopyToClipboard();
			}
		}

		/**
		 * Works on most modern browsers.
		 */
		_stdCopyToClipboard(){
			let initialType = this.$output.attr('type');
			this.$output.attr('type', 'text').select().select(); // 2 select() because Safari doesn't always understand the first time.

			let copyOk = this._doCopyToClipboard();

			this.$output.attr('type', initialType).blur();

			if(!copyOk){
				window.prompt('Copy to clipboard is not supported on your browser, please copy manually:', this.$output.val());
			}
		}

		/**
		 * Works on Safari iOS
		 * Thanks to https://stackoverflow.com/questions/34045777/copy-to-clipboard-using-javascript-in-ios
		 */
		_iOSCopyToClipboard(){
			let el = this.$output.get(0);
			let initialType = this.$output.attr("type");
			let range = document.createRange();

			this.$output
				.attr('type', 'text')
				.prop('contenteditable', true)
				.prop('readonly', false);

			range.selectNodeContents(el);

			var selection = window.getSelection();
			selection.removeAllRanges();
			selection.addRange(range);

			el.setSelectionRange(0, 255); // A big number, to cover anything that could be inside the element.

			this._doCopyToClipboard();

			this.$output
				.attr('type', initialType)
				.prop('contenteditable', false)
				.prop('readonly', true)
				.blur();
		}

		_doCopyToClipboard(){
			try {
				document.execCommand('copy');
				this.$copyOutput.width(this.$copyOutput.width()).html('<i class="fa fa-check"></i>');
				clearTimeout(this.copyTimeout);
				this.copyTimeout = setTimeout(() => {
					this.$copyOutput.html('Copy to clipboard');
				}, 1500);
				return true;
			} catch (err) {
				console.error(err);
			}
			return false;
		}
	}

	jQuery.fn.PasswordManager = function (settings) {
		return new PasswordManager($(this).eq(0), settings);
	};
})();