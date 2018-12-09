package com.xinsane.traffic_analysis.servlet;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.xinsane.traffic_analysis.Application;
import com.xinsane.traffic_analysis.helper.AESCryptHelper;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.List;

public class UploadServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("application/json; charset=UTF-8");
        if (!ServletFileUpload.isMultipartContent(request))
            throw new IllegalArgumentException("Request is not multipart.");
        PrintWriter writer = response.getWriter();
        JsonObject res = new JsonObject();
        JsonArray array = new JsonArray();
        try {
            ServletFileUpload uploadHandler = new ServletFileUpload(new DiskFileItemFactory());
            List<FileItem> items = uploadHandler.parseRequest(request);
            for (FileItem item : items) {
                if (!item.isFormField()) {
                    JsonObject object = new JsonObject();
                    object.addProperty("field", item.getFieldName());
                    object.addProperty("name", item.getName());
                    if (item.getName().toLowerCase().endsWith(".pcap")) {
                        object.addProperty("accept", true);
                        String filename = "upload-" + new SimpleDateFormat("yyyyMMddHHmmssSSS")
                                .format(System.currentTimeMillis()) + ".pcap";
                        object.addProperty("save_name", filename);
                        File file = new File(Application.dumper_dir, filename);
                        item.write(file);
                    }
                    else {
                        object.addProperty("accept", false);
                        object.addProperty("reject_reason", "文件后缀不允许");
                    }
                    array.add(object);
                }
            }
            res.addProperty("error", 0);
            res.addProperty("data", AESCryptHelper.encrypt(new Gson().toJson(array)));
        } catch (Exception e) {
            res.addProperty("error",1);
            res.addProperty("msg", AESCryptHelper.encrypt(e.getMessage()));
            throw new RuntimeException(e);
        } finally {
            writer.write(res.toString());
            writer.close();
        }
    }

}
