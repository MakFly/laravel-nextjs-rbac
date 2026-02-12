import { toast } from 'vue-sonner'

export function useNotification() {
  const success = (message: string, options?: any) => {
    return toast.success(message, options)
  }

  const error = (message: string, options?: any) => {
    return toast.error(message, options)
  }

  const info = (message: string, options?: any) => {
    return toast.info(message, options)
  }

  const warning = (message: string, options?: any) => {
    return toast.warning(message, options)
  }

  const promise = <T>(
    promise: Promise<T>,
    options: { loading: string; success: string; error: string }
  ) => {
    return toast.promise(promise, options)
  }

  return {
    success,
    error,
    info,
    warning,
    promise
  }
}
