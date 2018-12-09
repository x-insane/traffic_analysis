package com.xinsane.traffic_analysis.servlet;

import com.xinsane.traffic_analysis.Application;
import com.xinsane.traffic_analysis.helper.AESCryptHelper;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;

public class DownloadServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filename = request.getRequestURI().replace("/download/", "");
        String auth = AESCryptHelper.encrypt(filename);
        if (auth == null || !auth.equals(request.getParameter("auth"))) {
            response.setContentType("text/html; charset=utf-8");
            PrintWriter writer = response.getWriter();
            writer.println("403 Forbidden.");
            writer.close();
            return;
        }
        File file = new File(Application.dumper_dir + filename);
        if (filename.indexOf('/') == -1 && filename.indexOf('\\') == -1 &&
                file.exists() && file.isFile() && filename.toLowerCase().endsWith(".pcap")) {
            response.setContentType("application/octet-stream; charset=utf-8");
            response.setContentLengthLong(file.length());
            OutputStream outputStream = response.getOutputStream();
            FileInputStream inputStream = new FileInputStream(file);
            int length;
            byte[] buffer = new byte[1024];
            while ((length = inputStream.read(buffer)) != -1)
                outputStream.write(buffer, 0, length);
            inputStream.close();
            outputStream.close();
        } else {
            response.setContentType("text/html; charset=utf-8");
            PrintWriter writer = response.getWriter();
            writer.println("404 Not Found.");
            writer.close();
        }
    }

}
