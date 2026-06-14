window.HackitUI = {
  toast: (opts) => {
    const sw = window.SwalToast || Swal;
    sw.fire({
      icon: opts.icon || 'success',
      title: opts.title || '',
      text: opts.text || '',
      ...opts,
    });
  },

  confirm: async (opts) => {
    return Swal.fire({
      icon: opts.icon || 'warning',
      title: opts.title || 'Are you sure?',
      text: opts.text || '',
      showCancelButton: true,
      confirmButtonText: opts.confirmText || 'Yes, proceed',
      cancelButtonText: opts.cancelText || 'Cancel',
      reverseButtons: true,
      focusCancel: true,
      ...opts,
    });
  },

  loading: (title) => {
    Swal.fire({
      title: title || 'Processing...',
      allowOutsideClick: false,
      allowEscapeKey: false,
      showConfirmButton: false,
      didOpen: () => Swal.showLoading(),
    });
  },

  close: () => Swal.close(),

  input: async (opts) => {
    return Swal.fire({
      title: opts.title || 'Input',
      input: opts.input || 'text',
      inputPlaceholder: opts.placeholder || '',
      inputValue: opts.value || '',
      showCancelButton: true,
      confirmButtonText: opts.confirmText || 'OK',
      cancelButtonText: 'Cancel',
      reverseButtons: true,
      inputValidator: opts.validator || null,
      ...opts,
    });
  },

  error: (title, text) => {
    SwalToast.fire({ icon: 'error', title, text: text || '' });
  },

  success: (title, text) => {
    SwalToast.fire({ icon: 'success', title, text: text || '' });
  },

  info: (title, text) => {
    SwalToast.fire({ icon: 'info', title, text: text || '' });
  },
};
