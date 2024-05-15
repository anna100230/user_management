using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using NETCore.MailKit.Core;
using User.Management.ApI.Models;
using User.Management.Service.Models;
using User.Management.Service.Services;

var builder = WebApplication.CreateBuilder(args);

//For entity framework
var configuration = builder.Configuration;
builder.Services.AddDbContext<ApplicationDbContext>(Options=> Options.UseSqlServer(configuration.GetConnectionString("StudentCS")));

//for Identity
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders();
//Add config for Required email
builder.Services.Configure<IdentityOptions>(options =>options.SignIn.RequireConfirmedEmail=true);

//Adding Authentication
builder.Services.AddAuthentication(Options =>
{
    Options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    Options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;    
    Options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}
);
//Add email Configuration

var emailConfig = configuration.GetSection("EmailConfiguration").Get<EmailConfiguration>();
builder.Services.AddSingleton(emailConfig);

builder.Services.AddScoped<ITestServiece, TestService>();


// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
//For Authorization perpose
builder.Services.AddSwaggerGen(option =>
{
    option.SwaggerDoc("v1",new OpenApiInfo { Title ="Auth API", Version = "v1" });
    option.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description="Please enter a valid token",
        Name ="Authorization",
        Type = SecuritySchemeType.Http,
        BearerFormat = "JWT",
        Scheme ="Bearer"
    });
    option.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
           new OpenApiSecurityScheme
           {
            Reference= new OpenApiReference
            {
               Type = ReferenceType.SecurityScheme,
               Id = "Bearer"
            }
           },
        new string []{}
    }
    });
 
});
//builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
