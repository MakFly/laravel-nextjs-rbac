import Echo from 'laravel-echo';
import Pusher from 'pusher-js';

let echoInstance: Echo<'pusher'> | null = null;

export function getEcho(): Echo<'pusher'> {
  if (echoInstance) return echoInstance;

  if (typeof window === 'undefined') {
    throw new Error('Echo can only be used client-side');
  }

  // Make Pusher available globally (required by laravel-echo)
  (window as unknown as Record<string, unknown>).Pusher = Pusher;

  echoInstance = new Echo({
    broadcaster: 'pusher',
    key: process.env.NEXT_PUBLIC_REVERB_APP_KEY,
    wsHost: process.env.NEXT_PUBLIC_REVERB_HOST,
    wsPort: Number(process.env.NEXT_PUBLIC_REVERB_PORT),
    forceTLS: false,
    disableStats: true,
    enabledTransports: ['ws'],
    cluster: '',
  });

  return echoInstance;
}
