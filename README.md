# AWS IoT Android Client 
- 注册亚马逊账号 IoT，并且注册一个 things： https://us-east-2.console.aws.amazon.com/iot/home?region=us-east-2#/home
- 定义好策略、主题等设置；
- 下载步骤1注册things的证书，共三个 ```certificate_pem.crt```、```private_pem.key```以及```AmazonRootCA1.pem```；
- 把三个证书文件放在 ```app\src\main\res\raw``` 文件里面，并且确认 ```MainActivity.java``` 修改引入路径和文件名字；
