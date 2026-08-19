import { useEffect, useState } from 'react'
import { api } from './api'
import { LoadState } from './types'

export function useApi<T>(path: string): LoadState<T> & { reload: () => void } {
  const [state, setState] = useState<LoadState<T>>({ loading: true })
  const [version, setVersion] = useState(0)
  useEffect(() => {
    let active = true
    setState({ loading: true })
    api<T>(path)
      .then((data) => active && setState({ data, loading: false }))
      .catch((error: Error) => active && setState({ error: error.message, loading: false }))
    return () => {
      active = false
    }
  }, [path, version])
  return { ...state, reload: () => setVersion((value) => value + 1) }
}
