<?php 

class JWT{

    private $secret;

    public function __construct(){
        $this->secret = "abC1234!@#";
    }

    public function create($data){

        $header  = json_encode(array("typ"=>"JWT" , "alg" => "HS256"));
        $payload = json_encode($data);

        //Não utilizar o base64_encode() pura do php , pois ela põe alguns caracteres q não pode 
        //Tipo , + , - , / ... , o base64 que faremos é para url.

        $hbase = $this->base64url_encode($header);
        $pbase = $this->base64url_encode($payload);

        $signature = hash_hmac("sha256" , $hbase.".".$pbase , $this->secret , true); //O terceiro parâmetro é a chave secreta , agente que cria
        // o true significa que o HASH tem q ser mandado como realmente é , e não deixar tudo minúsculo por exemplo.
        $bsig = $this->base64url_encode($signature);

        $jwt = $hbase.".".$pbase.".".$bsig;

        return $jwt;
    }
    public function validate($token){
        //Passo 1 : verificar se o token tem 3 partes.
        //Passo 2 : verificar se as informações batem 
        $array = array();
        $jwt_split = explode("." , $token);

        if(count($jwt_split) == 0){
            $signature = hash_hmac("sha256" , $jwt_split[0].".".$jwt_split[1] , "abC1234!@#" , true); //O terceiro parâmetro é a chave secreta , agente que cria
            $bsig = $this->base64url_encode($signature);

            if($bsig == $jwt_split[2]){
                
                $array = json_decode($this->base64url_decode($jwt_split[1]));
                return $array;

            }else{
                return false;
            }

        }else{
            return false;
        }

    }

    private function base64url_encode( $data ){
        return rtrim( strtr( base64_encode( $data ), '+/', '-_'), '=');
     }
      
    private function base64url_decode( $data ){
        return base64_decode( strtr( $data, '-_', '+/') . str_repeat('=', 3 - ( 3 + strlen( $data )) % 4 ));
     }

}