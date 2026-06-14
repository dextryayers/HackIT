const swalTheme = {
  background: 'rgba(10,10,26,0.95)',
  color: '#f8fafc',
  confirmButtonColor: '#00d4ff',
  cancelButtonColor: '#1e293b',
  denyButtonColor: '#ff0040',
  backdrop: 'rgba(0,0,0,0.7)',
  customClass: {
    popup: 'rounded-2xl border border-border/50 shadow-premium-lg backdrop-blur-xl',
    title: 'text-lg font-bold text-white',
    htmlContainer: 'text-sm text-muted-foreground',
    confirmButton: 'px-5 py-2.5 rounded-xl bg-primary text-primary-foreground text-sm font-semibold border-0 cursor-pointer hover:shadow-glow-cyan transition-all duration-300',
    cancelButton: 'px-5 py-2.5 rounded-xl bg-card border border-border text-muted-foreground text-sm font-medium border-0 cursor-pointer hover:text-foreground transition-all duration-300',
    denyButton: 'px-5 py-2.5 rounded-xl bg-destructive text-destructive-foreground text-sm font-semibold border-0 cursor-pointer transition-all duration-300',
    input: 'w-full px-3.5 py-2.5 rounded-xl bg-card border border-border text-sm text-foreground placeholder-muted-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all',
    actions: 'gap-3',
    timerProgressBar: 'bg-gradient-to-r from-primary to-cyber-green',
    footer: 'text-xs text-muted-foreground',
  },
  showClass: {
    popup: 'animate-slide-up-fade',
    backdrop: 'animate-fade-in',
  },
  hideClass: {
    popup: 'animate-fade-out',
  },
  inputAttributes: {
    class: 'w-full px-3.5 py-2.5 rounded-xl bg-card border border-border text-sm text-foreground',
  },
};

if (typeof Swal !== 'undefined') {
  Swal.mixin(swalTheme);
  window.HackitSwal = Swal.mixin({
    ...swalTheme,
    toast: true,
    position: 'top-end',
    showConfirmButton: false,
    timer: 3000,
    timerProgressBar: true,
    didOpen: (toast) => {
      toast.addEventListener('mouseenter', Swal.stopTimer);
      toast.addEventListener('mouseleave', Swal.resumeTimer);
    },
  });
}
