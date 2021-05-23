/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2021 Luis Goncalves.
 *
 * XAdES4j is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or any later version.
 *
 * XAdES4j is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with XAdES4j. If not, see <http://www.gnu.org/licenses/>.
 */
package xades4j.production;

import xades4j.properties.DataObjectDesc;

import java.util.LinkedHashSet;
import java.util.Set;

// TODO javadocs
public final class EnvelopedManifest extends DataObjectDesc
{
    private final Set<DataObjectReference> dataObjs;

    public EnvelopedManifest()
    {
        this.dataObjs = new LinkedHashSet<DataObjectReference>(2);
    }

    public EnvelopedManifest withSignedDataObject(DataObjectReference object)
    {
        if (null == object)
        {
            throw new NullPointerException("Signed object description cannot be null");
        }

        if (!this.dataObjs.add(object))
        {
            throw new IllegalStateException("Data object description was already added");
        }
        return this;
    }

    public Iterable<DataObjectReference> getDataObjects()
    {
        return this.dataObjs;
    }
}
