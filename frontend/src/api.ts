export const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'
export async function api<T>(path:string, options:RequestInit={}):Promise<T>{
  const token=localStorage.getItem('helpdesk_session')
  const response=await fetch(`${API_URL}${path}`,{...options,headers:{'Content-Type':'application/json',...(token?{Authorization:`Bearer ${token}`} : {}),...options.headers}})
  if(response.status===401){localStorage.removeItem('helpdesk_session')}
  if(!response.ok){const body=await response.json().catch(()=>({detail:response.statusText}));throw new Error(body.detail||'Request failed')}
  if(response.status===204)return undefined as T
  return response.json()
}
