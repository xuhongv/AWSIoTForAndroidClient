package com.aws_iot;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.AppCompatButton;

import com.aws_iot.service.MqttAndroidClient;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.eclipse.paho.client.mqttv3.DisconnectedBufferOptions;
import org.eclipse.paho.client.mqttv3.IMqttActionListener;
import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.IMqttMessageListener;
import org.eclipse.paho.client.mqttv3.IMqttToken;
import org.eclipse.paho.client.mqttv3.MqttCallbackExtended;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class MainActivity extends AppCompatActivity {


    private MqttAndroidClient mqttAndroidClient;
    private final String TAG = "MqttAndroidClient";

    private final String serverUri = "ssl://a24mubm9eapydf-ats.iot.us-east-2.amazonaws.com:8883"; //http://wx.ai-thinker.com/

    private String clientId = "paho";
    final String subscriptionTopicResponse = "/device/property/response";
    final String subscriptionTopicInfo = "/device/property/info";
    final String publishTopic = "/device/property/request";


    // 证书信息
    private InputStream mCaCrtFile;
    private InputStream mCrtFile;
    private InputStream mKeyFile;

    //UI
    private TextView tvStatus, tvTemperature, tvHumidity, tvSoilMoisture, tvSoilPH, tvIlluminace, tvWaterLevel, tvMode;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initView();
        initCert();
        init_mqtt();
    }

    private void initView() {
        tvStatus = findViewById(R.id.tvStatus);
        tvTemperature = findViewById(R.id.tvTemperatur);
        tvHumidity = findViewById(R.id.tvHumidity);
        tvSoilMoisture = findViewById(R.id.tvSoilMoisture);
        tvSoilPH = findViewById(R.id.tvSoilPH);
        tvIlluminace = findViewById(R.id.tvIlluminace);
        tvWaterLevel = findViewById(R.id.tvWaterLevel);
        tvMode = findViewById(R.id.tvMode);
    }

    private void init_mqtt() {
        clientId = clientId + System.currentTimeMillis();

        Log.e(TAG, "clientId" + clientId);

        final MqttConnectOptions connOpts = new MqttConnectOptions();
        System.out.println("Connecting to broker: " + serverUri);
        try {
            connOpts.setServerURIs(new String[]{serverUri});
            connOpts.setSocketFactory(getSocketFactory(mCaCrtFile, mCrtFile, mKeyFile, ""));
            // MQTT clearSession 参数，设置确定是否继续接受离线消息
            connOpts.setCleanSession(false);
            // MQTT keepalive 参数，与离线时间有关，支持多久的掉线时间
            connOpts.setKeepAliveInterval(600);
            connOpts.setAutomaticReconnect(true);
        } catch (MqttException mqttException) {
            mqttException.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        mqttAndroidClient = new MqttAndroidClient(getApplicationContext(), serverUri, clientId);
        mqttAndroidClient.setCallback(new MqttCallbackExtended() {
            @Override
            public void connectComplete(boolean reconnect, String serverURI) {
                if (reconnect) {
                    Log.e(TAG, "Reconnected to : " + serverURI);
                    // Because Clean Session is true, we need to re-subscribe
                    subscribeToTopic();
                } else {
                    Log.e(TAG, "Connected to: " + serverURI);
                }
            }

            @Override
            public void connectionLost(Throwable cause) {
                Log.e(TAG, "The Connection was lost.");
            }

            @Override
            public void messageArrived(String topic, MqttMessage message) throws Exception {
                Log.e(TAG, "Incoming message: " + new String(message.getPayload()));
            }

            @Override
            public void deliveryComplete(IMqttDeliveryToken token) {

            }
        });

        try {
            //addToHistory("Connecting to " + serverUri);
            mqttAndroidClient.connect(connOpts, null, new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {
                    tvStatus.setText("connected");
                    tvStatus.setTextColor(getColor(R.color.greed));
                    Log.e(TAG, "OK to connect to: " + serverUri);
                    DisconnectedBufferOptions disconnectedBufferOptions = new DisconnectedBufferOptions();
                    disconnectedBufferOptions.setBufferEnabled(true);
                    disconnectedBufferOptions.setBufferSize(100);
                    disconnectedBufferOptions.setPersistBuffer(false);
                    disconnectedBufferOptions.setDeleteOldestMessages(false);
                    mqttAndroidClient.setBufferOpts(disconnectedBufferOptions);
                    subscribeToTopic();
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                    tvStatus.setText("disconnect");
                    tvStatus.setTextColor(getColor(R.color.red));
                    Log.e(TAG, "Failed to connect to server: " + serverUri);
                    Log.e(TAG, "Failed to connect to server getMessage: " + exception.getMessage());
                    Log.e(TAG, "Failed to connect to server asyncActionToken: " + asyncActionToken.getException().getMessage());
                }
            });


        } catch (MqttException ex) {
            ex.printStackTrace();
        }
    }


    // 初始化证书
    public void initCert() {
        try {

            mCaCrtFile = this.getResources().openRawResource(R.raw.root_ca);
            mCrtFile = this.getResources().openRawResource(R.raw.ertificate_pem);
            mKeyFile = this.getResources().openRawResource(R.raw.private_pem);

//            mCaCrtFile = this.getResources().openRawResource(R.raw.root_ca);
//            mCrtFile = this.getResources().openRawResource(R.raw.test_certificate_pem);
//            mKeyFile = this.getResources().openRawResource(R.raw.test_private_pem);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void subscribeToTopic() {
        try {
            mqttAndroidClient.subscribe(subscriptionTopicResponse, 0, null, new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {
                    Log.e(TAG, "Subscribed!");
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                    Log.e(TAG, "Failed to subscribe");
                }
            });

            // THIS DOES NOT WORK!
            mqttAndroidClient.subscribe(subscriptionTopicResponse, 0, new IMqttMessageListener() {
                @Override
                public void messageArrived(String topic, MqttMessage message) throws Exception {
                    // message Arrived!
                    Log.e(TAG, "Message: " + topic + " : " + new String(message.getPayload()));
                }
            });


            mqttAndroidClient.subscribe(subscriptionTopicInfo, 0, null, new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {
                    Log.e(TAG, "Subscribed!");
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                    Log.e(TAG, "Failed to subscribe");
                }
            });

            // THIS DOES NOT WORK!
            mqttAndroidClient.subscribe(subscriptionTopicInfo, 0, new IMqttMessageListener() {
                @Override
                public void messageArrived(String topic, MqttMessage message) throws Exception {
                    // message Arrived!
                    Log.e(TAG, "Message: " + topic + " ,payload: " + new String(message.getPayload()));

                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            String payload = new String(message.getPayload());
                            try {
                                JSONObject root = new JSONObject(payload);
                                JSONArray contentJson = root.getJSONArray("content");
                                // JSONObject infoJson = root.getJSONObject("info");
                                for (int i = 0; i < contentJson.length(); i++) {
                                    JSONObject itemJson = contentJson.getJSONObject(i);
                                    String key = itemJson.getString("key");
                                    switch (key) {
                                        case "Temperature":
                                            tvTemperature.setText("" + itemJson.getInt("value"));
                                            break;
                                        case "Humidity":
                                            tvHumidity.setText("" + itemJson.getInt("value"));
                                            break;
                                        case "SoilMoisture":
                                            tvSoilMoisture.setText("" + itemJson.getString("value"));
                                            break;
                                        case "SoilPH":
                                            tvSoilPH.setText("" + itemJson.getString("value"));
                                            break;
                                        case "Illuminace":
                                            tvIlluminace.setText(itemJson.getString("value"));
                                            break;
                                        case "Mode":
                                            tvMode.setText(itemJson.getString("value"));
                                            break;
                                        case "WaterLevel":
                                            tvWaterLevel.setText("" + itemJson.getInt("value"));
                                            break;
                                    }
                                }
                            } catch (JSONException e) {
                                Toast.makeText(getApplicationContext(), "Message Error", Toast.LENGTH_SHORT).show();
                                e.printStackTrace();
                            }
                        }
                    });
                }
            });


        } catch (MqttException ex) {
            Log.e(TAG, "Exception whilst subscribing");
            ex.printStackTrace();
        }
    }

    public void publishMessage(String publishMessage) {
        try {
            MqttMessage message = new MqttMessage();
            message.setPayload(publishMessage.getBytes());
            mqttAndroidClient.publish(publishTopic, message);
            Log.e(TAG, "Message Published");
            Log.e(TAG, "Message publishTopic:" + publishTopic);
            Log.e(TAG, "Message publishPayload:" + publishMessage);
            if (!mqttAndroidClient.isConnected()) {
                Log.e(TAG, mqttAndroidClient.getBufferedMessageCount() + " messages in buffer.");
            } else {

                Toast.makeText(this, "Message Published", Toast.LENGTH_SHORT).show();

            }
        } catch (MqttException e) {
            System.err.println("Error Publishing: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // SSLSocketFactory 实现双向TLS认证，因为IoT Core需要双向TLS认证
    public SSLSocketFactory getSocketFactory(InputStream caCrtFile, InputStream crtFile, InputStream keyFile,
                                             String password) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // load CA certificate
        X509Certificate caCert = null;

        BufferedInputStream bis = new BufferedInputStream(caCrtFile);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        while (bis.available() > 0) {
            caCert = (X509Certificate) cf.generateCertificate(bis);
        }
        // load client certificate
        bis = new BufferedInputStream(crtFile);
        X509Certificate cert = null;
        while (bis.available() > 0) {
            cert = (X509Certificate) cf.generateCertificate(bis);
        }
        // load client private cert
        PEMParser pemParser = new PEMParser(new InputStreamReader(keyFile));
        Object object = pemParser.readObject();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        KeyPair key = converter.getKeyPair((PEMKeyPair) object);

        KeyStore caKs = KeyStore.getInstance(KeyStore.getDefaultType());
        caKs.load(null, null);
        caKs.setCertificateEntry("cert-certificate", caCert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(caKs);

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setCertificateEntry("certificate", cert);
        ks.setKeyEntry("private-cert", key.getPrivate(), password.toCharArray(),
                new java.security.cert.Certificate[]{cert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, password.toCharArray());

        SSLContext context = SSLContext.getInstance("TLSv1.2");
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        return context.getSocketFactory();
    }


    private String getControlContent(String key, String value) {
        JSONObject root = new JSONObject();
        JSONObject content = new JSONObject();
        JSONArray commandValueArray = new JSONArray();
        try {
            root.put("timestamp", System.currentTimeMillis());
            JSONObject things = new JSONObject();
            things.put("key", key);
            things.put("value", value);
            commandValueArray.put(things);
            content.put("commandtype", "devicecontrol");
            content.put("commandvalue", commandValueArray);
            root.put("content", content);
            return root.toString();
        } catch (JSONException e) {
            e.printStackTrace();
            return "";
        }
    }

    // LED
    public void onClickLedHigh(View view) {
        publishMessage(getControlContent("led", "high"));
    }

    public void onClickLedMiddle(View view) {
        publishMessage(getControlContent("led", "mid"));
    }

    public void onClickLedLow(View view) {
        publishMessage(getControlContent("led", "low"));
    }

    public void onClickLedOff(View view) {
        publishMessage(getControlContent("led", "off"));
    }

    // Red
    public void onClickRedLedOn(View view) {
        publishMessage(getControlContent("led_red", "on"));
    }

    public void onClickRedLedOff(View view) {
        publishMessage(getControlContent("led_red", "off"));
    }

    public void onClickRedLedMiddle(View view) {
        publishMessage(getControlContent("led_red", "mid"));
    }

    public void onClickRedLedLow(View view) {
        publishMessage(getControlContent("led_red", "low"));
    }

    public void onClickRedLedHigh(View view) {
        publishMessage(getControlContent("led_red", "high"));
    }


    // Green
    public void onClickGreenLedOn(View view) {
        publishMessage(getControlContent("led_green", "on"));
    }

    public void onClickGreenLedOff(View view) {
        publishMessage(getControlContent("led_green", "off"));
    }

    public void onClickGreenLedMiddle(View view) {
        publishMessage(getControlContent("led_green", "mid"));
    }

    public void onClickGreenLedLow(View view) {
        publishMessage(getControlContent("led_green", "low"));
    }

    public void onClickGreenLedHigh(View view) {
        publishMessage(getControlContent("led_green", "high"));
    }


    // Blue
    public void onClickBlueLedOn(View view) {
        publishMessage(getControlContent("led_blue", "on"));
    }

    public void onClickBlueLedOff(View view) {
        publishMessage(getControlContent("led_blue", "off"));
    }

    public void onClickBlueLedMiddle(View view) {
        publishMessage(getControlContent("led_blue", "mid"));
    }

    public void onClickBlueLedLow(View view) {
        publishMessage(getControlContent("led_blue", "low"));
    }

    public void onClickBlueLedHigh(View view) {
        publishMessage(getControlContent("led_blue", "high"));
    }


    // Fan
    public void onClickFanLedOn(View view) {
        publishMessage(getControlContent("fan", "on"));
    }

    public void onClickFanLedOff(View view) {
        publishMessage(getControlContent("fan", "off"));
    }


    // Water
    public void onClickWaterLedOn(View view) {
        publishMessage(getControlContent("water", "on"));
    }

    public void onClickWaterLedOff(View view) {
        publishMessage(getControlContent("water", "off"));
    }


    //自动模式
    public void onClickManualOn(View view) {
        publishMessage(getControlContent("Mode", "Manual"));
    }

    public void onClickAutoOff(View view) {
        publishMessage(getControlContent("Mode", "Auto"));
    }

}