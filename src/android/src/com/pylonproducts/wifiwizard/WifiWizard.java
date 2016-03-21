/*
 * Copyright
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package com.pylonproducts.wifiwizard;

import org.apache.cordova.*;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.spec.ECField;
import java.util.List;

import android.app.IntentService;
import android.os.Build;
import android.Manifest;
import android.content.pm.PackageManager;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.net.NetworkInfo;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiEnterpriseConfig;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.SupplicantState;
import android.content.Context;
import android.util.Log;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import android.location.LocationManager;
import org.apache.cordova.LOG;
import android.content.Intent;
import android.net.Uri;

import android.provider.Settings;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;

import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;

public class WifiWizard extends CordovaPlugin {
private static final String LOG_TAG = "CordovaPermissionHelper";
    private static final String ADD_NETWORK = "addNetwork";
    private static final String REMOVE_NETWORK = "removeNetwork";
    private static final String CONNECT_NETWORK = "connectNetwork";
    private static final String DISCONNECT_NETWORK = "disconnectNetwork";
    private static final String DISCONNECT = "disconnect";
    private static final String LIST_NETWORKS = "listNetworks";
    private static final String START_SCAN = "startScan";
    private static final String GET_SCAN_RESULTS = "getScanResults";
    private static final String GET_CONNECTED_SSID = "getConnectedSSID";
    private static final String IS_WIFI_ENABLED = "isWifiEnabled";
    private static final String CREATE_SERVER = "createServer";
    private static final String SET_WIFI_ENABLED = "setWifiEnabled";
    private static final String TAG = "WifiWizard";
    private static final String SOCKET_HANDSHAKE_MESSAGE = "hey, are you asfalio app?";
    private static final String SOCKET_HANDSHAKE_RESPONSE = "yes";
    private static  final int port = 7371;

    private WifiManager wifiManager;
    private CallbackContext callbackContext;
    public static CallbackContext socketCallbackContext;

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        this.wifiManager = (WifiManager) cordova.getActivity().getSystemService(Context.WIFI_SERVICE);

    }

    @Override
    public boolean execute(String action, JSONArray data, CallbackContext callbackContext)
                            throws JSONException {

        this.callbackContext = callbackContext;

        if(action.equals(CREATE_SERVER)){
            Log.d(TAG,"createserver called");
            socketCallbackContext=callbackContext;

            this.cordova.getActivity().runOnUiThread(new Runnable() {

                @Override
                public void run() {
                    createServer();
                }
            });

           return true;
        }

        if(!displayLocationSettingsRequest()){
            callbackContext.error("Android 6 and above Gps turned off");
        }

        if(!checkCurrentPermissions()){
            callbackContext.error("permission not found") ;
        }

        if(action.equals(IS_WIFI_ENABLED)) {
            return this.isWifiEnabled(callbackContext);
        }
        else if(action.equals(SET_WIFI_ENABLED)) {
            return this.setWifiEnabled(callbackContext, data);
        }
        else if (!wifiManager.isWifiEnabled()) {
            callbackContext.error("Wifi is not enabled.");
            return false;
        }
        else if(action.equals(ADD_NETWORK)) {
            return this.addNetwork(callbackContext, data);
        }
        else if(action.equals(REMOVE_NETWORK)) {
            return this.removeNetwork(callbackContext, data);
        }
        else if(action.equals(CONNECT_NETWORK)) {
            return this.connectNetwork(callbackContext, data);
        }
        else if(action.equals(DISCONNECT_NETWORK)) {
            return this.disconnectNetwork(callbackContext, data);
        }
        else if(action.equals(LIST_NETWORKS)) {
            return this.listNetworks(callbackContext);
        }
        else if(action.equals(START_SCAN)) {
            return this.startScan(callbackContext);
        }
        else if(action.equals(GET_SCAN_RESULTS)) {
            return this.getScanResults(callbackContext, data);
        }
        else if(action.equals(DISCONNECT)) {
            return this.disconnect(callbackContext);
        }
        else if(action.equals(GET_CONNECTED_SSID)) {
            return this.getConnectedSSID(callbackContext);
        }
        else {
            callbackContext.error("Incorrect action parameter: " + action);
        }

        return false;
    }

    public static void  respondToClientSuccess(String message){
        PluginResult result = new PluginResult(PluginResult.Status.OK, message);
        result.setKeepCallback(true);
        socketCallbackContext.sendPluginResult(result);
    }
    public static void  respondToClientError(String message){
        try {
            PluginResult result = new PluginResult(PluginResult.Status.ERROR, message);
            result.setKeepCallback(true);
            socketCallbackContext.sendPluginResult(result);
        }catch (Exception e){e.printStackTrace();}
    }

    public void createServer(){

        cordova.getActivity().startService(new Intent(cordova.getActivity(), MyService.class));
    }

    public boolean checkCurrentPermissions(){
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !thasPermission(this,Manifest.permission.ACCESS_COARSE_LOCATION)) {
            trequestPermissions(this,1,new String[]{Manifest.permission.ACCESS_COARSE_LOCATION, Manifest.permission.ACCESS_FINE_LOCATION});
            return false;
         }
         else return true;
    }
    public static void trequestPermissions(CordovaPlugin plugin, int requestCode, String[] permissions) {
            try {
                Method requestPermission = CordovaInterface.class.getDeclaredMethod(
                        "requestPermissions", CordovaPlugin.class, int.class, String[].class);

                // If there is no exception, then this is cordova-android 5.0.0+
                requestPermission.invoke(plugin.cordova, plugin, requestCode, permissions);
            } catch (NoSuchMethodException noSuchMethodException) {
                // cordova-android version is less than 5.0.0, so permission is implicitly granted
                LOG.d(LOG_TAG, "No need to request permissions " + Arrays.toString(permissions));

                // Notify the plugin that all were granted by using more reflection
                deliverPermissionResult(plugin, requestCode, permissions);
            } catch (IllegalAccessException illegalAccessException) {
                // Should never be caught; this is a public method
                LOG.e(LOG_TAG, "IllegalAccessException when requesting permissions " + Arrays.toString(permissions), illegalAccessException);
            } catch(InvocationTargetException invocationTargetException) {
                // This method does not throw any exceptions, so this should never be caught
                LOG.e(LOG_TAG, "invocationTargetException when requesting permissions " + Arrays.toString(permissions), invocationTargetException);
            }
        }


         public static boolean thasPermission(CordovaPlugin plugin, String permission) {
                try {
                    Method hasPermission = CordovaInterface.class.getDeclaredMethod("hasPermission", String.class);

                    // If there is no exception, then this is cordova-android 5.0.0+
                    return (Boolean) hasPermission.invoke(plugin.cordova, permission);
                } catch (NoSuchMethodException noSuchMethodException) {
                    // cordova-android version is less than 5.0.0, so permission is implicitly granted
                    LOG.d(LOG_TAG, "No need to check for permission " + permission);
                    return true;
                } catch (IllegalAccessException illegalAccessException) {
                    // Should never be caught; this is a public method
                    LOG.e(LOG_TAG, "IllegalAccessException when checking permission " + permission, illegalAccessException);
                } catch(InvocationTargetException invocationTargetException) {
                    // This method does not throw any exceptions, so this should never be caught
                    LOG.e(LOG_TAG, "invocationTargetException when checking permission " + permission, invocationTargetException);
                }
                return false;
            }

            private static void deliverPermissionResult(CordovaPlugin plugin, int requestCode, String[] permissions) {
                    // Generate the request results
                    int[] requestResults = new int[permissions.length];
                    Arrays.fill(requestResults, PackageManager.PERMISSION_GRANTED);

                    try {
                        Method onRequestPermissionResult = CordovaPlugin.class.getDeclaredMethod(
                                "onRequestPermissionResult", int.class, String[].class, int[].class);

                        onRequestPermissionResult.invoke(plugin, requestCode, permissions, requestResults);
                    } catch (NoSuchMethodException noSuchMethodException) {
                        // Should never be caught since the plugin must be written for cordova-android 5.0.0+ if it
                        // made it to this point
                        LOG.e(LOG_TAG, "NoSuchMethodException when delivering permissions results", noSuchMethodException);
                    } catch (IllegalAccessException illegalAccessException) {
                        // Should never be caught; this is a public method
                        LOG.e(LOG_TAG, "IllegalAccessException when delivering permissions results", illegalAccessException);
                    } catch(InvocationTargetException invocationTargetException) {
                        // This method may throw a JSONException. We are just duplicating cordova-android's
                        // exception handling behavior here; all it does is log the exception in CordovaActivity,
                        // print the stacktrace, and ignore it
                        LOG.e(LOG_TAG, "InvocationTargetException when delivering permissions results", invocationTargetException);
                    }
                }


                private boolean displayLocationSettingsRequest() {
                  Context context=this.cordova.getActivity().getApplicationContext();

                   LocationManager lm = (LocationManager)context.getSystemService(Context.LOCATION_SERVICE);
                   boolean gps_enabled = false;
                   if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M){

                   try {
                       gps_enabled = lm.isProviderEnabled(LocationManager.GPS_PROVIDER);

                   } catch(Exception ex) {

                   }
                   }else{
                    return true;
                   }

                   return gps_enabled;

                }





    /**
     * This methods adds a network to the list of available WiFi networks.
     * If the network already exists, then it updates it.
     *
     * @params callbackContext     A Cordova callback context.
     * @params data                JSON Array with [0] == SSID, [1] == password
     * @return true    if add successful, false if add fails
     */
    private boolean addNetwork(CallbackContext callbackContext, JSONArray data) {
        // Initialize the WifiConfiguration object

         try {
        String password = data.getString(2);
        String SSID = data.getString(0);


        WifiConfiguration wifi = new WifiConfiguration();
                         wifi.SSID =  SSID;
                        wifi.status = WifiConfiguration.Status.DISABLED;
                        wifi.priority = 1000;

        Log.d(TAG, "WifiWizard: addNetwork entered.");


            // data's order for ANY object is 0: ssid, 1: authentication algorithm,
            // 2+: authentication information.
            String authType = data.getString(1);


            if (authType.equals("WPA")) {
                // WPA Data format:
                // 0: ssid
                // 1: auth
                // 2: password
                String newSSID = data.getString(0);
                //wifi.SSID = newSSID;
                String newPass = data.getString(2);
                wifi.preSharedKey = newPass;

                wifi.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
                wifi.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
                wifi.allowedProtocols.set(WifiConfiguration.Protocol.WPA);
                wifi.allowedAuthAlgorithms.clear();
                wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
                wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
                wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40);
                wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP104);
                wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
                wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);


                wifi.networkId = ssidToNetworkId(newSSID);

                if ( wifi.networkId == -1 ) {

                    wifiManager.addNetwork(wifi);
                    callbackContext.success(newSSID + " successfully added WPA WIFI ");
                }
                else {
                    wifiManager.updateNetwork(wifi);
                    callbackContext.success(newSSID + " successfully updated  WPA WIFI ");
                }

                wifiManager.saveConfiguration();
                return true;

            }
            else if (authType.equals("WEP")) {
                // TODO: connect/configure for WEP

                    wifi.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
                    wifi.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
                    wifi.allowedProtocols.set(WifiConfiguration.Protocol.WPA);
                    wifi.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);
                    wifi.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.SHARED);
                    wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
                    wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
                    wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40);
                    wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP104);


                    wifi.wepKeys[0] =password;
                    wifi.wepTxKeyIndex = 0;

                    wifi.networkId = ssidToNetworkId(SSID);

                if ( wifi.networkId == -1 ) {

                    wifiManager.addNetwork(wifi);
                    callbackContext.success(SSID + " successfully added. WEP WIFI");
                }
                else {
                    wifiManager.updateNetwork(wifi);
                    callbackContext.success(SSID + " successfully updated. WEP WIFI");
                }

                wifiManager.saveConfiguration();
                return true;

            }
            else if(authType.equals("WPA2")){

                wifi.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
                wifi.allowedProtocols.set(WifiConfiguration.Protocol.WPA);
                wifi.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);
                wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
                wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
                wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40);
                wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP104);
                wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
                wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
                wifi.preSharedKey = password;

                wifi.networkId = ssidToNetworkId(SSID);

                if ( wifi.networkId == -1 ) {

                    wifiManager.addNetwork(wifi);
                    callbackContext.success(SSID + " successfully added WPA2 WIFI ");
                }
                else {
                    wifiManager.updateNetwork(wifi);
                    callbackContext.success(SSID + " successfully updated  WPA2 WIFI ");
                }

                wifiManager.saveConfiguration();
                wifiManager.setWifiEnabled(true);
                wifiManager.enableNetwork(ssidToNetworkId(SSID),true);

                return true;

            }

            else if (authType.equals("NONE")) {
                String newSSID = data.getString(0);
                wifi.SSID = newSSID;
                wifi.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
                wifi.networkId = ssidToNetworkId(newSSID);

                if ( wifi.networkId == -1 ) {
                    wifiManager.addNetwork(wifi);
                    callbackContext.success(newSSID + " successfully added.");
                }
                else {
                    wifiManager.updateNetwork(wifi);
                    callbackContext.success(newSSID + " successfully updated.");
                }

                wifiManager.saveConfiguration();
                return true;
            }
            // TODO: Add more authentications as necessary
            else {
                Log.d(TAG, "Wifi Authentication Type Not Supported.");
                callbackContext.error("Wifi Authentication Type Not Supported: " + authType);
                return false;
            }
        }
        catch (Exception e) {
            callbackContext.error(Log.getStackTraceString(e));
            Log.d(TAG,e.getMessage());
            return false;
        }
    }

    /**
     *    This method removes a network from the list of configured networks.
     *
     *    @param    callbackContext        A Cordova callback context
     *    @param    data                JSON Array, with [0] being SSID to remove
     *    @return    true if network removed, false if failed
     */
    private boolean removeNetwork(CallbackContext callbackContext, JSONArray data) {
        Log.d(TAG, "WifiWizard: removeNetwork entered.");

        if(!validateData(data)) {
            callbackContext.error("WifiWizard: removeNetwork data invalid");
            Log.d(TAG, "WifiWizard: removeNetwork data invalid");
            return false;
        }

        // TODO: Verify the type of data!
        try {
            String ssidToDisconnect = data.getString(0);

            int networkIdToRemove = ssidToNetworkId(ssidToDisconnect);

            if (networkIdToRemove >= 0) {
                wifiManager.removeNetwork(networkIdToRemove);
                wifiManager.saveConfiguration();
                callbackContext.success("Network removed.");
                return true;
            }
            else {
                callbackContext.error("Network not found.");
                Log.d(TAG, "WifiWizard: Network not found, can't remove.");
                return false;
            }
        }
        catch (Exception e) {
            callbackContext.error(e.getMessage());
            Log.d(TAG, e.getMessage());
            return false;
        }
    }

    /**
     *    This method connects a network.
     *
     *    @param    callbackContext        A Cordova callback context
     *    @param    data                JSON Array, with [0] being SSID to connect
     *    @return    true if network connected, false if failed
     */
    private boolean connectNetwork(CallbackContext callbackContext, JSONArray data) {
        Log.d(TAG, "WifiWizard: connectNetwork entered.");
        if(!validateData(data)) {
            callbackContext.error("WifiWizard: connectNetwork invalid data");
            Log.d(TAG, "WifiWizard: connectNetwork invalid data.");
            return false;
        }
        String ssidToConnect = "";

        try {
            ssidToConnect = data.getString(0);
        }
        catch (Exception e) {
            callbackContext.error(e.getMessage());
            Log.d(TAG, e.getMessage());
            return false;
        }

        int networkIdToConnect = ssidToNetworkId(ssidToConnect);

        if (networkIdToConnect >= 0) {
            // We disable the network before connecting, because if this was the last connection before
            // a disconnect(), this will not reconnect.

            wifiManager.setWifiEnabled(true);
            wifiManager.disableNetwork(networkIdToConnect);
            wifiManager.enableNetwork(networkIdToConnect, true);

            SupplicantState supState;
            WifiInfo wifiInfo = wifiManager.getConnectionInfo();
            supState = wifiInfo.getSupplicantState();
            callbackContext.success(supState.toString());
            return true;

        }else{
            callbackContext.error("WifiWizard: cannot connect to network");
            return false;
        }
    }

    /**
     *    This method disconnects a network.
     *
     *    @param    callbackContext        A Cordova callback context
     *    @param    data                JSON Array, with [0] being SSID to connect
     *    @return    true if network disconnected, false if failed
     */
    private boolean disconnectNetwork(CallbackContext callbackContext, JSONArray data) {
    Log.d(TAG, "WifiWizard: disconnectNetwork entered.");
        if(!validateData(data)) {
            callbackContext.error("WifiWizard: disconnectNetwork invalid data");
            Log.d(TAG, "WifiWizard: disconnectNetwork invalid data");
            return false;
        }
        String ssidToDisconnect = "";
        // TODO: Verify type of data here!
        try {
            ssidToDisconnect = data.getString(0);
        }
        catch (Exception e) {
            callbackContext.error(e.getMessage());
            Log.d(TAG, e.getMessage());
            return false;
        }

        int networkIdToDisconnect = ssidToNetworkId(ssidToDisconnect);

        if (networkIdToDisconnect > 0) {
            wifiManager.disableNetwork(networkIdToDisconnect);
            callbackContext.success("Network " + ssidToDisconnect + " disconnected!");
            return true;
        }
        else {
            callbackContext.error("Network " + ssidToDisconnect + " not found!");
            Log.d(TAG, "WifiWizard: Network not found to disconnect.");
            return false;
        }
    }

    /**
     *    This method disconnects current network.
     *
     *    @param    callbackContext        A Cordova callback context
     *    @return    true if network disconnected, false if failed
     */
    private boolean disconnect(CallbackContext callbackContext) {
        Log.d(TAG, "WifiWizard: disconnect entered.");
        if (wifiManager.disconnect()) {
            callbackContext.success("Disconnected from current network");
            return true;
        } else {
            callbackContext.error("Unable to disconnect from the current network");
            return false;
        }
    }

    /**
     *    This method uses the callbackContext.success method to send a JSONArray
     *    of the currently configured networks.
     *
     *    @param    callbackContext        A Cordova callback context
                JSON Array, with [0] being SSID to connect
     *    @return    true if network disconnected, false if failed
     */
    private boolean listNetworks(CallbackContext callbackContext) {
        Log.d(TAG, "WifiWizard: listNetworks entered.");
        List<WifiConfiguration> wifiList = wifiManager.getConfiguredNetworks();

        JSONArray returnList = new JSONArray();

        for (WifiConfiguration wifi : wifiList) {
            returnList.put(wifi.SSID);
        }

        callbackContext.success(returnList);

        return true;
    }

    /**
       *    This method uses the callbackContext.success method to send a JSONArray
       *    of the scanned networks.
       *
       *    @param    callbackContext        A Cordova callback context
       *    @param    data                   JSONArray with [0] == JSONObject
       *    @return    true
       */
    private boolean getScanResults(CallbackContext callbackContext, JSONArray data) {
        List<ScanResult> scanResults = wifiManager.getScanResults();

        JSONArray returnList = new JSONArray();

        Integer numLevels = null;

        if(!validateData(data)) {
            callbackContext.error("WifiWizard: disconnectNetwork invalid data");
            Log.d(TAG, "WifiWizard: disconnectNetwork invalid data");
            return false;
        }else if (!data.isNull(0)) {
            try {
                JSONObject options = data.getJSONObject(0);

                if (options.has("numLevels")) {
                    Integer levels = options.optInt("numLevels");

                    if (levels > 0) {
                        numLevels = levels;
                    } else if (options.optBoolean("numLevels", false)) {
                        // use previous default for {numLevels: true}
                        numLevels = 5;
                    }
                }
            } catch (JSONException e) {
                e.printStackTrace();
                callbackContext.error(e.toString());
                return false;
            }
        }

        for (ScanResult scan : scanResults) {
            /*
             * @todo - breaking change, remove this notice when tidying new release and explain changes, e.g.:
             *   0.y.z includes a breaking change to WifiWizard.getScanResults().
             *   Earlier versions set scans' level attributes to a number derived from wifiManager.calculateSignalLevel.
             *   This update returns scans' raw RSSI value as the level, per Android spec / APIs.
             *   If your application depends on the previous behaviour, we have added an options object that will modify behaviour:
             *   - if `(n == true || n < 2)`, `*.getScanResults({numLevels: n})` will return data as before, split in 5 levels;
             *   - if `(n > 1)`, `*.getScanResults({numLevels: n})` will calculate the signal level, split in n levels;
             *   - if `(n == false)`, `*.getScanResults({numLevels: n})` will use the raw signal level;
             */

            int level;

            if (numLevels == null) {
              level = scan.level;
            } else {
              level = wifiManager.calculateSignalLevel(scan.level, numLevels);
            }

            JSONObject lvl = new JSONObject();
            try {
                lvl.put("level", level);
                lvl.put("SSID", scan.SSID);
                lvl.put("BSSID", scan.BSSID);
                lvl.put("frequency", scan.frequency);
                lvl.put("capabilities", scan.capabilities);
               // lvl.put("timestamp", scan.timestamp);
                returnList.put(lvl);
            } catch (JSONException e) {
                e.printStackTrace();
                callbackContext.error(e.toString());
                return false;
            }
        }

        callbackContext.success(returnList);
        return true;
    }

    /**
       *    This method uses the callbackContext.success method. It starts a wifi scanning
       *
       *    @param    callbackContext        A Cordova callback context
       *    @return    true if started was successful
       */
    private boolean startScan(CallbackContext callbackContext) {
        if (wifiManager.startScan()) {
            callbackContext.success();
            return true;
        }
        else {
            callbackContext.error("Scan failed");
            return false;
        }
    }

    /**
     * This method retrieves the SSID for the currently connected network
     *
     *    @param    callbackContext        A Cordova callback context
     *    @return    true if SSID found, false if not.
    */
    private boolean getConnectedSSID(CallbackContext callbackContext){
        if(!wifiManager.isWifiEnabled()){
            callbackContext.error("Wifi is disabled");
            return false;
        }

        WifiInfo info = wifiManager.getConnectionInfo();

        if(info == null){
            callbackContext.error("Unable to read wifi info");
            return false;
        }

        String ssid = info.getSSID();
        if(ssid.isEmpty()) {
            ssid = info.getBSSID();
        }
        if(ssid.isEmpty()){
            callbackContext.error("SSID is empty");
            return false;
        }

        callbackContext.success(ssid);
        return true;
    }

    /**
     * This method retrieves the current WiFi status
     *
     *    @param    callbackContext        A Cordova callback context
     *    @return    true if WiFi is enabled, fail will be called if not.
    */
    private boolean isWifiEnabled(CallbackContext callbackContext) {
        boolean isEnabled = wifiManager.isWifiEnabled();
        callbackContext.success(isEnabled ? "1" : "0");
        return isEnabled;
    }

    /**
     *    This method takes a given String, searches the current list of configured WiFi
     *     networks, and returns the networkId for the network if the SSID matches. If not,
     *     it returns -1.
     */
    private int ssidToNetworkId(String ssid) {
        List<WifiConfiguration> currentNetworks = wifiManager.getConfiguredNetworks();
        int networkId = -1;

        // For each network in the list, compare the SSID with the given one
        for (WifiConfiguration test : currentNetworks) {
            if ( test.SSID.equals(ssid) ) {
                networkId = test.networkId;
            }
        }

        return networkId;
    }

    /**
     *    This method enables or disables the wifi
     */
    private boolean setWifiEnabled(CallbackContext callbackContext, JSONArray data) {
        if(!validateData(data)) {
            callbackContext.error("WifiWizard: disconnectNetwork invalid data");
            Log.d(TAG, "WifiWizard: disconnectNetwork invalid data");
            return false;
        }

        String status = "";

        try {
            status = data.getString(0);
        }
        catch (Exception e) {
            callbackContext.error(e.getMessage());
            Log.d(TAG, e.getMessage());
            return false;
        }

        if (wifiManager.setWifiEnabled(status.equals("true"))) {
            callbackContext.success();
            return true;
        }
        else {
            callbackContext.error("Cannot enable wifi");
            return false;
        }
    }

    private boolean validateData(JSONArray data) {
        try {
            if (data == null || data.get(0) == null) {
                callbackContext.error("Data is null.");
                return false;
            }
            return true;
        }
        catch (Exception e) {
            callbackContext.error(e.getMessage());
        }
        return false;
    }


    public static class MyService extends IntentService {
        public MyService() {
            super("MyService");
        }
        @Override
        protected void onHandleIntent(Intent intent) {
            Log.d(TAG, "onHandleIntent");

            ServerSocket listener = null;
            try {
                listener = new ServerSocket();
                listener.setReuseAddress(true);
                listener.bind(new InetSocketAddress(port));
                Log.d(TAG, String.format("listening on port = %d", port));
                while (true) {
                    Log.d(TAG, "waiting for client");
                    Socket socket = listener.accept();
                    Log.d(TAG, String.format("client connected from: %s", socket.getRemoteSocketAddress().toString()));
                    if(socketCallbackContext!=null) {
                        try {

                            respondToClientSuccess("{'name':'" + socket.getRemoteSocketAddress().toString() + "'}");
                        }catch (Exception e){
                            e.printStackTrace();
                            socket.close();

                            Log.d(TAG,"closing socket");
                            break;

                        }
                    }else{
                        socket.close();
                        Log.d(TAG,"closing socket");
                        Log.d(TAG,"callback is null");
                        break;
                    }
                    BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    PrintStream out = new PrintStream(socket.getOutputStream());
                    for (String inputLine; (inputLine = in.readLine()) != null;) {
                        Log.d(TAG, "received");
                        Log.d(TAG, inputLine);
                        if(socketCallbackContext!=null) {
                            try {
                                respondToClientSuccess("{'name':'" + socket.getRemoteSocketAddress().toString() + "','message':'" + inputLine + "'}");
                            }
                            catch (Exception e){
                                Log.d(TAG,"closing socket");
                                e.printStackTrace();
                                socket.close();
                            }
                         }
                        else{
                            Log.d(TAG,"closing socket");
                            socket.close();
                            Log.d(TAG,"callback is null");
                        }

                        /*
                        OutputStream os = socket.getOutputStream();
                        OutputStreamWriter osw = new OutputStreamWriter(os);
                        BufferedWriter bw = new BufferedWriter(osw);
                        bw.write("IamApp");
                        bw.flush();
                        */

                        //socketCallbackContext
                        if(inputLine.equals(SOCKET_HANDSHAKE_MESSAGE)) {
                            StringBuilder outputStringBuilder = new StringBuilder(SOCKET_HANDSHAKE_RESPONSE);
                            out.println(outputStringBuilder);
                        }else{
                            Log.d(TAG,inputLine);
                            Log.d(TAG,"unknown message");
                        }

                    }
                }
            } catch(IOException e) {
                respondToClientError("error");
                Log.d(TAG, e.toString());
            }
        }
    }
}
