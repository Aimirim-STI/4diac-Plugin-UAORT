/*******************************************************************************
 * Copyright (c) 2024 AIMIRIM STI - https://en.aimirimsti.com.br/
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0/.
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *   Pedro Ricardo
 *   Felipe Adriano
 *******************************************************************************/

package com.asti.fordiac.ide.deployment.uao.helpers;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

enum TypeSize {
	FALSE(0), TRUE(0), SINT(1), INT(2), DINT(4), LINT(8), USINT(1), UINT(2), UDINT(4), ULINT(8), REAL(4), LREAL(8),
	TIME(8), LTIME(8), DATE(8), LDATE(8), DT(8), LDT(8), STRING(-1), BYTE(1), WORD(2), DWORD(4), LWORD(8), ARRAY(-1);

	private final int sz;

	TypeSize(final int s) {
		sz = s;
	}

	public int getSz() {
		return (sz);
	}

}

enum TypeID {
	FALSE((byte) 0x40), TRUE((byte) 0x41), SINT((byte) 0x42), INT((byte) 0x43), DINT((byte) 0x44), LINT((byte) 0x45),
	USINT((byte) 0x46), UINT((byte) 0x47), UDINT((byte) 0x48), ULINT((byte) 0x49), REAL((byte) 0x4A),
	LREAL((byte) 0x4B), TIME((byte) 0x4C), LTIME((byte) 0x57), DATE((byte) 0x4D), LDATE((byte) 0x58), DT((byte) 0x4F),
	LDT((byte) 0x5E), STRING((byte) 0x50), BYTE((byte) 0x51), WORD((byte) 0x52), DWORD((byte) 0x53), LWORD((byte) 0x54),
	ARRAY((byte) 0x56);

	private final byte id;

	TypeID(final byte b) {
		id = b;
	}

	public byte getId() {
		return (id);
	}

	public static TypeID fromId(final byte some_id) {
		for (final TypeID type : values()) {
			if (type.getId() == some_id) {
				return type;
			}
		}
		return null;
	}
}

public class Watches {

	private static class BufferPos {

		public BufferPos(final int n) {
			p = n;
		}

		private int p;

		public int getP() {
			return p;
		}

		public void incP(final int n) {
			this.p += n;
		}
	}

	/**
	 * Description
	 *
	 * @param data
	 * @return
	 */
	public static List<String> decodeWatchData(final byte[] data) {
		final List<String> values = new ArrayList<>();
		final BufferPos pos = new Watches.BufferPos(0);

		final int buffer_size = data.length;
		final ByteBuffer buffer = ByteBuffer.wrap(data);
		String tmp_val = ""; //$NON-NLS-1$
		TypeID id;

		while (pos.getP() < buffer_size) {
			tmp_val = ""; //$NON-NLS-1$
			id = TypeID.fromId(buffer.get(pos.getP()));
			pos.incP(TypeSize.BYTE.getSz());
			if (id == TypeID.ARRAY) {
				tmp_val = decodeArrayType(buffer, pos);
			} else {
				tmp_val = decodeDataType(buffer, pos, id);
			}
			values.add(tmp_val);
		}

		return (values);
	}

	/**
	 * Description
	 *
	 * @param buffer
	 * @param pos
	 * @return
	 */
	private static String decodeArrayType(final ByteBuffer buffer, final BufferPos pos) {
		String value = ""; //$NON-NLS-1$

		final short arr_size = buffer.getShort(pos.getP());
		pos.incP(TypeSize.INT.getSz());

		final TypeID id = TypeID.fromId(buffer.get(pos.getP()));
		pos.incP(TypeSize.BYTE.getSz());

		value += "["; //$NON-NLS-1$
		for (int i = 0; i < arr_size; i++) {
			value += decodeDataType(buffer, pos, id) + " , "; //$NON-NLS-1$
		}
		value.replaceFirst("\s*,\s*$", ""); //$NON-NLS-1$ //$NON-NLS-2$
		value += "]"; //$NON-NLS-1$

		return (value);
	}

	/**
	 * Description
	 *
	 * @param buffer
	 * @param pos
	 * @return
	 */
	private static String decodeDataType(final ByteBuffer buffer, final BufferPos pos, final TypeID id) {
		String value = ""; //$NON-NLS-1$

		switch (id) {
		case FALSE:
			value = "FALSE"; //$NON-NLS-1$
			break;
		case TRUE:
			value = "TRUE"; //$NON-NLS-1$
			break;
		case SINT:
			value = Byte.toString(buffer.get(pos.getP()));
			pos.incP(TypeSize.SINT.getSz());
			break;
		case INT:
			value = String.valueOf(buffer.getShort(pos.getP()));
			pos.incP(TypeSize.INT.getSz());
			break;
		case DINT:
			value = String.valueOf(buffer.getInt(pos.getP()));
			pos.incP(TypeSize.DINT.getSz());
			break;
		case LINT:
			value = String.valueOf(buffer.getLong(pos.getP()));
			pos.incP(TypeSize.LINT.getSz());
			break;
		case BYTE:
		case USINT:
			value = String.valueOf(Byte.toUnsignedInt(buffer.get(pos.getP())));
			pos.incP(TypeSize.USINT.getSz());
			break;
		case WORD:
		case UINT:
			value = Integer.toUnsignedString(buffer.getShort(pos.getP()));
			pos.incP(TypeSize.UINT.getSz());
			break;
		case DWORD:
		case UDINT:
			value = Integer.toUnsignedString(buffer.getInt(pos.getP()));
			pos.incP(TypeSize.UDINT.getSz());
			break;
		case LWORD:
		case ULINT:
			value = Long.toUnsignedString(buffer.getLong(pos.getP()));
			pos.incP(TypeSize.ULINT.getSz());
			break;
		case REAL:
			value = String.valueOf(buffer.getFloat(pos.getP()));
			pos.incP(TypeSize.REAL.getSz());
			break;
		case LREAL:
			value = String.valueOf(buffer.getDouble(pos.getP()));
			pos.incP(TypeSize.LREAL.getSz());
			break;
		case TIME:
			// FIXME: Add an intelligent and dynamic representation of Time. Currently fixed
			// in [ms] unit
			final long mili = buffer.getLong(pos.getP()) / 1000;
			value = "T#" + Long.toUnsignedString(mili) + "ms"; //$NON-NLS-1$ //$NON-NLS-2$
			pos.incP(TypeSize.TIME.getSz());
			break;
		case LTIME:
			// FIXME: Missing Time representation string
			value = Long.toUnsignedString(buffer.getLong(pos.getP()));
			pos.incP(TypeSize.LTIME.getSz());
			break;
		case DATE:
			// FIXME: Missing Date representation string
			value = Long.toUnsignedString(buffer.getLong(pos.getP()));
			pos.incP(TypeSize.DATE.getSz());
			break;
		case LDATE:
			// FIXME: Missing Date representation string
			value = Long.toUnsignedString(buffer.getLong(pos.getP()));
			pos.incP(TypeSize.LDATE.getSz());
			break;
		case DT:
			// FIXME: Missing Time Delta representation string
			value = Long.toUnsignedString(buffer.getLong(pos.getP()));
			pos.incP(TypeSize.DT.getSz());
			break;
		case LDT:
			// FIXME: Missing Time Delta representation string
			value = Long.toUnsignedString(buffer.getLong(pos.getP()));
			pos.incP(TypeSize.LDT.getSz());
			break;
		case STRING:
			final short str_size = buffer.getShort(pos.getP());
			pos.incP(TypeSize.INT.getSz());
			final byte[] str_bytes = Arrays.copyOfRange(buffer.array(), pos.getP(), pos.getP()+str_size);
			value = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(str_bytes)).toString();
            pos.incP(str_size);
            // Adding surrounding single quotes to string watch:
            value = "'"+value+"'"; //$NON-NLS-1$ //$NON-NLS-2$
			break;
		default:
			// Non implemented
			value = "N/I"; //$NON-NLS-1$
			break;
		}

		return (value);
	}

}
