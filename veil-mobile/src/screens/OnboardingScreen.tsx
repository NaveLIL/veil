import React, { useState } from "react";
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  ScrollView,
} from "react-native";
import VeilCrypto from "../native/crypto";
import { useAuthStore } from "../stores/auth";

export default function OnboardingScreen() {
  const [mnemonic, setMnemonic] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const { setMnemonic: storeMnemonic, setIdentityKey } = useAuthStore();

  const handleGenerate = async () => {
    setLoading(true);
    const m = await VeilCrypto.generateMnemonic();
    setMnemonic(m);
    setLoading(false);
  };

  const handleConfirm = async () => {
    if (!mnemonic) return;
    setLoading(true);
    const key = await VeilCrypto.createIdentity(mnemonic);
    storeMnemonic(mnemonic);
    setIdentityKey(key);
    setLoading(false);
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>VEIL</Text>
      <Text style={styles.subtitle}>
        End-to-end encrypted messenger.{"\n"}Your keys never leave this device.
      </Text>

      {!mnemonic ? (
        <TouchableOpacity
          style={styles.button}
          onPress={handleGenerate}
          disabled={loading}
        >
          <Text style={styles.buttonText}>Create New Identity</Text>
        </TouchableOpacity>
      ) : (
        <>
          <ScrollView style={styles.mnemonicBox}>
            <Text style={styles.mnemonicText}>{mnemonic}</Text>
          </ScrollView>
          <Text style={styles.warning}>
            Write down these words. They are your only recovery method.
          </Text>
          <TouchableOpacity
            style={styles.button}
            onPress={handleConfirm}
            disabled={loading}
          >
            <Text style={styles.buttonText}>I've saved my phrase</Text>
          </TouchableOpacity>
        </>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#0a0a0f",
    alignItems: "center",
    justifyContent: "center",
    padding: 32,
  },
  title: {
    fontSize: 36,
    fontWeight: "300",
    color: "#e5e5e5",
    letterSpacing: 8,
    marginBottom: 12,
  },
  subtitle: {
    color: "#888",
    textAlign: "center",
    marginBottom: 40,
    lineHeight: 22,
  },
  mnemonicBox: {
    backgroundColor: "#16161e",
    borderRadius: 12,
    padding: 20,
    maxHeight: 160,
    width: "100%",
    borderWidth: 1,
    borderColor: "#2a2a35",
    marginBottom: 16,
  },
  mnemonicText: {
    color: "#e5e5e5",
    fontFamily: "monospace",
    fontSize: 16,
    lineHeight: 28,
    textAlign: "center",
  },
  warning: {
    color: "#f59e0b",
    fontSize: 13,
    textAlign: "center",
    marginBottom: 24,
  },
  button: {
    backgroundColor: "#6366f1",
    paddingHorizontal: 28,
    paddingVertical: 14,
    borderRadius: 10,
  },
  buttonText: {
    color: "#fff",
    fontSize: 16,
    fontWeight: "600",
  },
});
