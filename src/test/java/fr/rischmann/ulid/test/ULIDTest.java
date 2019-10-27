package fr.rischmann.ulid.test;

import fr.rischmann.ulid.ULID;
import org.junit.Test;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.*;

public class ULIDTest {
    @Test
    public void newWithData() {
        final String s = "01DQKAB1JGXYHT5EDBBFVTM1Z9";

        ULID exp = ULID.fromString(s);
        assertNotNull(exp);

        ULID id = new ULID(exp.getData());
        assertNotNull(id);

        assertArrayEquals(exp.getData(), id.getData());
    }

    @Test(expected = IllegalArgumentException.class)
    public void parseInvalidSize() {
        ULID.fromString("foobar");
    }

    @Test(expected = IllegalArgumentException.class)
    public void parseOverflowing() {
        ULID.fromString("81DQKAB1JGXYHT5EDBBFVTM1Z9");
    }

    @Test(expected = IllegalArgumentException.class)
    public void parseInvalidCharacters() {
        ULID.fromString("0==QKAB1JGXYHT5EDBBFVTM1Z9");
    }

    @Test
    public void inSet() {
        Set<ULID> set = new HashSet<>();

        ULID id = ULID.random(0, new SecureRandom());

        set.add(id);
        set.add(id);

        assertEquals(1, set.size());
    }

    @Test
    public void parseValid() {
        final String s = "01DQKAB1JGXYHT5EDBBFVTM1Z9";

        ULID id = ULID.fromString(s);
        assertNotNull(id);
        assertEquals(s, id.toString());

        long timestamp = id.getTimestamp();
        long expected = 1571532670544L;
        assertEquals(expected, timestamp);

        Instant time = Instant.ofEpochMilli(timestamp);
        assertEquals("2019-10-20T00:51:10.544Z", time.toString());
    }

    @Test
    public void random() {
        final Instant time = Instant.now();
        final long timestamp = time.toEpochMilli();

        ULID id = ULID.random(timestamp, new SecureRandom());
        assertNotNull(id);
        assertEquals(timestamp, id.getTimestamp());

        String s = id.toString();
        assertEquals(ULID.ENCODED_SIZE, s.length());

        ULID id2 = ULID.fromString(s);
        assertEquals(id2, id);

        Instant time2 = Instant.ofEpochMilli(id.getTimestamp());
        assertEquals(time.toEpochMilli(), time2.toEpochMilli());
    }
}
