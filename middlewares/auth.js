import jwt from 'jsonwebtoken'
const JWT_SECRET = process.env.JWT_SECRET

const auth = (req,res,next) => {
  const token = req.headers.authorization
  console.log(token)

  if(!token){
    return res.status(401).json({message:'Acesso Negado'})
  }
  try{
    const decoded = jwt.verify(token.replace('Bearer',''),JWT_SECRET)

} catch(err){
    return res.ststus(401).json({message:'Token invalido'})
    
}

}


export default auth