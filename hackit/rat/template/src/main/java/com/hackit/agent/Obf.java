package com.hackit.agent;

/**
 * Build-time string table. The builder XOR-encodes every sensitive literal and
 * writes {@code Strings.java}; nothing readable stays in the dex constant pool.
 * Decoding is a single pass into a small cache, then the array is cleared.
 */
public final class Obf {
    private static final int KEY = 0x5A;
    private static String[] table = Strings.TABLE;

    static String s(int index) {
        if (table == null || index < 0 || index >= table.length) {
            return "";
        }
        String encoded = table[index];
        if (encoded == null) {
            return "";
        }
        if (encoded.startsWith("\u0001")) {
            return encoded.substring(1);
        }
        char[] chars = encoded.toCharArray();
        for (int i = 0; i < chars.length; i++) {
            chars[i] = (char) (chars[i] ^ (KEY + (i & 0x1F)));
        }
        String value = new String(chars);
        table[index] = "\u0001" + value;
        return value;
    }

    static int size() {
        return table == null ? 0 : table.length;
    }

    private Obf() {
    }
}