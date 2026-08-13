package com.rkp.gateway.xml;

import com.fasterxml.jackson.dataformat.xml.XmlFactory;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.fasterxml.jackson.dataformat.xml.deser.FromXmlParser;
import org.springframework.stereotype.Component;

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
import java.io.StringReader;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class XmlCodec {

    private final XmlMapper mapper = XmlMapper.builder(new XmlFactory()).build();

    public Map<String, String> parse(String xml) {
        try {
            XMLStreamReader reader = mapper.getFactory()
                    .getXMLInputFactory()
                    .createXMLStreamReader(new StringReader(xml));

            Map<String, String> result = new LinkedHashMap<>();
            String current = null;

            while (reader.hasNext()) {
                int event = reader.next();

                if (event == XMLStreamConstants.START_ELEMENT) {
                    current = reader.getLocalName();
                } else if (event == XMLStreamConstants.CHARACTERS) {
                    if (current != null) {
                        String value = reader.getText().trim();
                        if (!value.isEmpty() && !"root".equals(current)) {
                            result.put(current, value);
                        }
                    }
                } else if (event == XMLStreamConstants.END_ELEMENT) {
                    current = null;
                }
            }

            reader.close();
            return result;

        } catch (Exception e) {
            throw new RuntimeException("Invalid XML: " + xml, e);
        }
    }

    public String build(Map<String, String> fields) {
        StringBuilder sb = new StringBuilder(128);
        sb.append("<root>");
        for (Map.Entry<String, String> e : fields.entrySet()) {
            sb.append('<').append(e.getKey()).append('>')
              .append(e.getValue())
              .append("</").append(e.getKey()).append('>' );
        }
        sb.append("</root>");
        return sb.toString();
    }

    public String type(Map<String, String> m) {
        return m.getOrDefault("rec", "");
    }

    public String msgId(Map<String, String> m) {
        return m.getOrDefault("msgId", "");
    }
    
    public static void main(String[] args) {
		System.out.println(new XmlCodec().parse("<root><rec>ECHO</rec><msgId>1001</msgId></root>"));
	}
}