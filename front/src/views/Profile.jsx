import axios from 'axios'
import Context from '../contexts/Context'
import { useContext, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { ENDPOINT } from '../config/constans'

const Profile = () => {
  const navigate = useNavigate()
  const { getDeveloper, setDeveloper } = useContext(Context)

  const getDeveloperData = () => {
    const token = window.sessionStorage.getItem('token');
    axios.get(ENDPOINT.users, { headers: { Authorization: `Bearer ${token}` } })
        .then(({ data }) => {
            console.log("Datos del usuario:", data);
            setDeveloper(data);
        })
        .catch(({ response }) => {
            console.error("Error:", response?.data || "Error desconocido");
            window.sessionStorage.removeItem('token');
            setDeveloper(null);
            navigate('/');
        })
}
  useEffect(getDeveloperData, [])

  return (
    <div className='py-5'>
      <h1>
        Bienvenido <span className='fw-bold'>{getDeveloper?.email}</span>
      </h1>
      <h3>
        {getDeveloper?.rol} en {getDeveloper?.lenguage}
      </h3>
    </div>
  )
}

export default Profile
